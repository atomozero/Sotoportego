/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "GeoLookup.h"

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

#include <Message.h>
#include <OS.h>
#include <String.h>


namespace GeoLookup {

const char* const kFieldCountry		= "soto:geo:country";
const char* const kFieldQueryIP		= "soto:geo:queryIP";
const char* const kFieldLatitude	= "soto:geo:lat";
const char* const kFieldLongitude	= "soto:geo:lon";

// ip-api.com supports a plain-text "line" format keyed by the fields you
// request. We had been using `/line?fields=...` but ip-api ignores the
// order in the fields= parameter and returns its own canonical ordering,
// which silently put the lat value where we expected the IP and vice
// versa -- the self pin ended up in the Pacific. The /json endpoint keys
// the values by name so the order is irrelevant; the schema is flat and
// simple enough that we parse it inline rather than pull in a JSON
// dependency for the daemon.
static const char* const kHost		= "ip-api.com";
static const int kPort				= 80;
static const char* const kPath		= "/json?fields=country,query,lat,lon";

// Total wall-clock budget for the request -- connect, write, read. If the
// VPN's egress blocks port 80 or ip-api throttles us, we'd rather time out
// quickly and fall back to a country-less notification than make the user
// wait.
static const int kTimeoutSeconds	= 4;

}	// namespace GeoLookup


struct LookupArgs {
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


// Synchronous HTTP/1.0 GET. Returns the response body (trimmed) on success,
// or an empty BString on any failure.
static BString
http_get(const char* host, int port, const char* path)
{
	struct hostent* he = gethostbyname(host);
	if (he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL)
		return BString();

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return BString();

	// Don't leak this short-lived socket into any openvpn child the
	// backend may spawn while we are mid-lookup.
	fcntl(sock, F_SETFD, FD_CLOEXEC);

	set_socket_timeout(sock, GeoLookup::kTimeoutSeconds);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(sock);
		return BString();
	}

	BString request;
	request << "GET " << path << " HTTP/1.0\r\n"
		<< "Host: " << host << "\r\n"
		<< "User-Agent: Sotoportego\r\n"
		<< "Accept: text/plain\r\n"
		<< "Connection: close\r\n\r\n";

	const char* req = request.String();
	size_t left = request.Length();
	while (left > 0) {
		ssize_t sent = send(sock, req, left, 0);
		if (sent <= 0) {
			close(sock);
			return BString();
		}
		req += sent;
		left -= sent;
	}

	BString response;
	char buf[1024];
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
		// A read error or SO_RCVTIMEO timeout (EAGAIN/EWOULDBLOCK) leaves us
		// with a partial JSON body; treating it as EOF would feed truncated
		// JSON to the parser. Fail the lookup instead (empty == failure).
		close(sock);
		return BString();
	}
	close(sock);

	int32 bodyStart = response.FindFirst("\r\n\r\n");
	if (bodyStart < 0)
		return BString();
	BString body;
	response.CopyInto(body, bodyStart + 4,
		response.Length() - bodyStart - 4);
	body.Trim();

	// The /json endpoint always starts with '{'; anything else is an
	// error page (rate limit HTML, captive-portal interception, etc.).
	if (body.Length() == 0 || body[0] == '<')
		return BString();
	return body;
}


// Find the next char (typically " or }) past the value that starts at
// `from` in `body`. Returns -1 if not found. Used to extract the substring
// between two quotes or up to the next , / }.
static int32
find_value_end(const BString& body, int32 from, const char* stops)
{
	for (int32 i = from; i < body.Length(); i++) {
		char c = body[i];
		for (const char* s = stops; *s != '\0'; s++) {
			if (c == *s)
				return i;
		}
	}
	return -1;
}


// Extract a string value from a flat JSON object: looks for "key":"...".
// Returns empty BString on miss. No escape handling; ip-api's `country`
// and `query` are plain ASCII, so the simple version is enough.
static BString
json_string(const BString& body, const char* key)
{
	BString needle("\"");
	needle << key << "\":\"";
	int32 start = body.FindFirst(needle);
	if (start < 0)
		return BString();
	start += needle.Length();
	int32 end = find_value_end(body, start, "\"");
	if (end < 0)
		return BString();
	BString out;
	body.CopyInto(out, start, end - start);
	return out;
}


// Extract a numeric value: "key":<number>[,}]. Returns true on hit.
static bool
json_number(const BString& body, const char* key, float& outValue)
{
	BString needle("\"");
	needle << key << "\":";
	int32 start = body.FindFirst(needle);
	if (start < 0)
		return false;
	start += needle.Length();
	int32 end = find_value_end(body, start, ",}");
	if (end < 0)
		return false;
	BString numStr;
	body.CopyInto(numStr, start, end - start);
	numStr.Trim();
	outValue = (float)atof(numStr.String());
	return true;
}


static int32
lookup_thread(void* arg)
{
	LookupArgs* args = (LookupArgs*)arg;

	BString body = http_get(GeoLookup::kHost, GeoLookup::kPort,
		GeoLookup::kPath);

	BMessage result(args->what);
	if (body.Length() > 0) {
		BString country = json_string(body, "country");
		if (country.Length() > 0)
			result.AddString(GeoLookup::kFieldCountry, country);
		BString query = json_string(body, "query");
		if (query.Length() > 0)
			result.AddString(GeoLookup::kFieldQueryIP, query);
		float lat = 0.0f;
		// ip-api sends 0 for unknown locations; treat exact-zero as missing
		// so we don't claim Null Island as anyone's home.
		if (json_number(body, "lat", lat) && lat != 0.0f)
			result.AddFloat(GeoLookup::kFieldLatitude, lat);
		float lon = 0.0f;
		if (json_number(body, "lon", lon) && lon != 0.0f)
			result.AddFloat(GeoLookup::kFieldLongitude, lon);
	}
	args->target.SendMessage(&result);

	delete args;
	return B_OK;
}


void
GeoLookup::BackgroundLookup(const BMessenger& target, uint32 what)
{
	if (!target.IsValid())
		return;

	LookupArgs* args = new LookupArgs;
	args->target = target;
	args->what = what;

	thread_id thread = spawn_thread(lookup_thread, "geo-lookup",
		B_LOW_PRIORITY, args);
	if (thread < B_OK) {
		delete args;
		return;
	}
	resume_thread(thread);
}
