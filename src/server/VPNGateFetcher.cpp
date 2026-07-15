/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VPNGateFetcher.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <vector>

#include <Message.h>
#include <OS.h>
#include <String.h>

#include "CountryCentroids.h"
#include "VPNProtocol.h"


namespace {

static const char* const kHost			= "www.vpngate.net";
static const int kPort					= 80;
static const char* const kPath			= "/api/iphone/";

// The CSV blob is a few megabytes; give the fetch a generous deadline so a
// slow connection over the LAN side doesn't cut us off mid-row, but not so
// long that the user gives up.
static const int kConnectTimeoutSeconds	= 6;
static const int kIOTimeoutSeconds		= 25;

// VPNGate's CSV header (line 2 of the response, after the leading "*vpn_..."
// comment) lists these columns in this order. The fetch is brittle to
// reordering of columns, but VPNGate has kept the schema stable for years.
enum CsvColumn {
	kColHostName	= 0,
	kColIP			= 1,
	kColScore		= 2,
	kColPing		= 3,
	kColSpeed		= 4,
	kColCountryLong	= 5,
	kColCountryShort = 6,
	kColSessions	= 7,
	kColUptime		= 8,
	kColTotalUsers	= 9,
	kColTotalTraffic = 10,
	kColLogType		= 11,
	kColOperator	= 12,
	kColMessage		= 13,
	kColConfigData	= 14,
	kColExpected	= 15
};


struct FetchArgs {
	BMessenger	target;
	uint32		what;
};


static void
set_socket_timeout(int fd, int seconds)
{
	struct timeval tv;
	tv.tv_sec = seconds;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}


// HTTP/1.0 GET that returns the raw response body. Big (several MB) is
// expected; the buffer doubles as needed via BString::Append.
static bool
http_get(const char* host, int port, const char* path, BString& bodyOut,
	BString& errorOut)
{
	struct hostent* he = gethostbyname(host);
	if (he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL) {
		errorOut = "DNS lookup failed for ";
		errorOut << host;
		return false;
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		errorOut = "Could not create socket";
		return false;
	}
	fcntl(sock, F_SETFD, FD_CLOEXEC);
	set_socket_timeout(sock, kConnectTimeoutSeconds);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		errorOut = "Connect to vpngate.net failed";
		close(sock);
		return false;
	}

	// Bump the read timeout now that we are past the connect phase: the
	// response is a few MB and the server can dribble it out slowly.
	set_socket_timeout(sock, kIOTimeoutSeconds);

	BString request;
	request << "GET " << path << " HTTP/1.0\r\n"
		<< "Host: " << host << "\r\n"
		<< "User-Agent: Sotoportego\r\n"
		<< "Accept: text/csv, */*\r\n"
		<< "Connection: close\r\n\r\n";

	const char* req = request.String();
	size_t left = request.Length();
	while (left > 0) {
		ssize_t sent = send(sock, req, left, 0);
		if (sent <= 0) {
			errorOut = "Send failed";
			close(sock);
			return false;
		}
		req += sent;
		left -= sent;
	}

	BString response;
	char buf[8192];
	while (true) {
		ssize_t got = recv(sock, buf, sizeof(buf), 0);
		if (got > 0) {
			response.Append(buf, got);
			continue;
		}
		if (got == 0)
			break;			// peer closed cleanly: the body is complete
		if (errno == EINTR)
			continue;		// interrupted before any data; retry
		// got < 0 with a real error. SO_RCVTIMEO surfaces here as EAGAIN/
		// EWOULDBLOCK -- if we treated that as a clean EOF (as the old
		// `got <= 0` did) we would silently accept a truncated multi-MB
		// catalogue as complete, mangling the last CSV row's base64 config.
		// Fail loudly instead.
		close(sock);
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			errorOut = "Timed out reading response from vpngate.net";
		else
			errorOut = "Read error while fetching from vpngate.net";
		return false;
	}
	close(sock);

	int32 bodyStart = response.FindFirst("\r\n\r\n");
	if (bodyStart < 0) {
		errorOut = "Malformed HTTP response";
		return false;
	}
	response.CopyInto(bodyOut, bodyStart + 4,
		response.Length() - bodyStart - 4);
	return true;
}


// Split a CSV line on commas. VPNGate doesn't quote fields or escape commas
// inside them (the only "free text" columns are Operator/Message, which the
// owners keep ASCII-only), so a plain split is enough.
static void
split_csv_line(const BString& line, std::vector<BString>& fields)
{
	int32 start = 0;
	int32 length = line.Length();
	for (int32 i = 0; i <= length; i++) {
		if (i == length || line.ByteAt(i) == ',') {
			BString piece;
			line.CopyInto(piece, start, i - start);
			fields.push_back(piece);
			start = i + 1;
		}
	}
}


// Iterate over `body` newline-by-newline, calling visit() for each non-empty
// trimmed line that isn't the leading `*vpn_servers` comment or the trailing
// `*` end marker.
template<typename Visit>
static void
for_each_csv_line(const BString& body, Visit visit)
{
	int32 length = body.Length();
	int32 start = 0;
	for (int32 i = 0; i <= length; i++) {
		bool atEnd = (i == length);
		char c = atEnd ? '\n' : body.ByteAt(i);
		if (c != '\n')
			continue;

		BString line;
		body.CopyInto(line, start, i - start);
		start = i + 1;

		// Strip a trailing CR (the response is HTTP/CRLF) and any
		// surrounding whitespace.
		while (line.Length() > 0
				&& (line.ByteAt(line.Length() - 1) == '\r'
					|| line.ByteAt(line.Length() - 1) == ' '
					|| line.ByteAt(line.Length() - 1) == '\t')) {
			line.Truncate(line.Length() - 1);
		}
		if (line.Length() == 0)
			continue;
		// Skip the catalogue's pseudo-lines: the leading `*vpn_servers`
		// banner, the closing `*` end marker, and the `#HostName,...`
		// column-header line (VPNGate prefixes the schema row with '#').
		if (line.ByteAt(0) == '*' || line.ByteAt(0) == '#')
			continue;

		visit(line);
	}
}


// Pull a column out of a row safely. Returns "" if the column doesn't exist
// (e.g. a row that has the trailing config but no operator).
static BString
field_or_empty(const std::vector<BString>& fields, size_t index)
{
	if (index >= fields.size())
		return BString();
	return fields[index];
}


static int32
fetch_thread(void* arg)
{
	FetchArgs* args = (FetchArgs*)arg;

	BString body;
	BString error;
	bool ok = http_get(kHost, kPort, kPath, body, error);

	BMessage result(args->what);

	if (!ok || body.Length() == 0) {
		if (error.Length() == 0)
			error = "Empty response from vpngate.net";
		result.AddString(kFieldError, error);
		args->target.SendMessage(&result);
		delete args;
		return B_OK;
	}

	int32 servers = 0;
	int32 skippedHeader = 0;	// the column-name row arrives before any data

	for_each_csv_line(body, [&](const BString& line) {
		std::vector<BString> fields;
		split_csv_line(line, fields);

		// The first non-comment line of the response is the column header.
		// We don't strictly need it -- the column order is fixed -- but
		// skip it before parsing data rows.
		if (skippedHeader == 0 && fields.size() > 0
				&& fields[0] == "HostName") {
			skippedHeader = 1;
			return;
		}

		if (fields.size() < kColExpected)
			return;

		BString host    = field_or_empty(fields, kColHostName);
		BString ip      = field_or_empty(fields, kColIP);
		BString ccLong  = field_or_empty(fields, kColCountryLong);
		BString ccShort = field_or_empty(fields, kColCountryShort);
		BString config  = field_or_empty(fields, kColConfigData);

		if (host.Length() == 0 || config.Length() == 0)
			return;

		float lat = 0, lon = 0;
		if (!CountryCentroids::Lookup(ccShort, lat, lon)) {
			// Hide servers we can't place rather than dropping them on
			// (0, 0) in the Atlantic.
			return;
		}

		BMessage entry;
		entry.AddString(kFieldVPNGateHost, host);
		if (ip.Length() > 0)
			entry.AddString(kFieldVPNGateIP, ip);
		entry.AddString(kFieldVPNGateCountryShort, ccShort);
		entry.AddString(kFieldVPNGateCountryLong, ccLong);
		entry.AddInt32(kFieldVPNGateScore,
			(int32)strtol(field_or_empty(fields, kColScore).String(),
				NULL, 10));
		entry.AddInt32(kFieldVPNGatePing,
			(int32)strtol(field_or_empty(fields, kColPing).String(),
				NULL, 10));
		// Speed is reported in bits/second; render Mbps for the UI.
		long speedBits = strtol(field_or_empty(fields, kColSpeed).String(),
			NULL, 10);
		entry.AddInt32(kFieldVPNGateSpeedMbps,
			(int32)(speedBits / (1000L * 1000L)));
		entry.AddInt32(kFieldVPNGateSessions,
			(int32)strtol(field_or_empty(fields, kColSessions).String(),
				NULL, 10));
		entry.AddString(kFieldVPNGateLogPolicy,
			field_or_empty(fields, kColLogType));
		entry.AddFloat(kFieldVPNGateLatitude, lat);
		entry.AddFloat(kFieldVPNGateLongitude, lon);
		entry.AddString(kFieldVPNGateConfigBase64, config);

		result.AddMessage(kFieldVPNGateServer, &entry);
		servers++;
	});

	if (servers == 0) {
		result.AddString(kFieldError,
			"vpngate.net response had no usable servers");
	}

	printf("[VPNGate] fetched %" B_PRId32 " server(s)\n", servers);

	args->target.SendMessage(&result);
	delete args;
	return B_OK;
}

}	// namespace


void
VPNGateFetcher::BackgroundFetch(const BMessenger& target, uint32 whatOnReady)
{
	if (!target.IsValid())
		return;

	FetchArgs* args = new FetchArgs;
	args->target = target;
	args->what = whatOnReady;

	thread_id thread = spawn_thread(fetch_thread, "vpngate-fetch",
		B_LOW_PRIORITY, args);
	if (thread < B_OK) {
		delete args;
		return;
	}
	resume_thread(thread);
}
