/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "MagicSock.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>

#include "TSStun.h"


namespace ts {

// The disco magic ("TS💬") that prefixes every disco datagram.
static const uint8 kDiscoMagic[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };

// STUN's magic cookie (RFC 5389), at byte offset 4 of every STUN message.
static const uint8 kStunCookie[4] = { 0x21, 0x12, 0xa4, 0x42 };


MagicSock::MagicSock()
	:
	fSocket(-1),
	fPort(0)
{
}


MagicSock::~MagicSock()
{
	Close();
}


status_t
MagicSock::Open(uint16 port)
{
	if (fSocket >= 0)
		return B_NOT_ALLOWED;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return B_ERROR;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		close(sock);
		return B_ERROR;
	}

	// Learn the actual (possibly ephemeral) bound port.
	struct sockaddr_in bound;
	socklen_t boundLen = sizeof(bound);
	if (getsockname(sock, (struct sockaddr*)&bound, &boundLen) == 0)
		fPort = ntohs(bound.sin_port);
	else
		fPort = port;

	// A short receive timeout so a reader loop can check a stop flag.
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	fSocket = sock;
	return B_OK;
}


void
MagicSock::Close()
{
	if (fSocket >= 0) {
		close(fSocket);
		fSocket = -1;
	}
	fPort = 0;
}


ssize_t
MagicSock::SendTo(const struct sockaddr* to, socklen_t toLen, const void* buf,
	size_t len)
{
	if (fSocket < 0)
		return -1;
	return sendto(fSocket, buf, len, 0, to, toLen);
}


ssize_t
MagicSock::Recv(void* buf, size_t cap, struct sockaddr_storage* from,
	socklen_t* fromLen)
{
	if (fSocket < 0)
		return -1;
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	ssize_t n = recvfrom(fSocket, buf, cap, 0, (struct sockaddr*)&ss, &sl);
	if (n >= 0 && from != NULL) {
		memcpy(from, &ss, sl < (socklen_t)sizeof(*from) ? sl : sizeof(*from));
		if (fromLen != NULL)
			*fromLen = sl;
	}
	return n;
}


status_t
MagicSock::DiscoverEndpoint(const char* stunHost, uint16 stunPort,
	BString& outIP, uint16& outPort)
{
	if (fSocket < 0 || stunHost == NULL)
		return B_NO_INIT;

	char portStr[8];
	snprintf(portStr, sizeof(portStr), "%u", (unsigned)stunPort);
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	struct addrinfo* res = NULL;
	if (getaddrinfo(stunHost, portStr, &hints, &res) != 0 || res == NULL)
		return B_NAME_NOT_FOUND;

	uint8 req[20];
	uint8 txId[12];
	StunBuildRequest(req, txId);

	status_t result = B_TIMED_OUT;
	// A few attempts; each Recv is bounded by the socket's 1s timeout.
	for (int attempt = 0; attempt < 3 && result != B_OK; attempt++) {
		if (SendTo(res->ai_addr, res->ai_addrlen, req, sizeof(req))
				!= (ssize_t)sizeof(req))
			continue;
		// Read datagrams until the STUN reply arrives (ignore disco/WG that
		// might land on the shared socket meanwhile) or we time out.
		for (int i = 0; i < 8; i++) {
			uint8 buf[512];
			ssize_t n = Recv(buf, sizeof(buf), NULL, NULL);
			if (n <= 0)
				break;	// timeout for this attempt
			if (Classify(buf, (size_t)n) != PKT_STUN)
				continue;
			if (StunParseResponse(buf, (size_t)n, txId, outIP, outPort)) {
				result = B_OK;
				break;
			}
		}
	}

	freeaddrinfo(res);
	return result;
}


SockPacketKind
MagicSock::Classify(const uint8* buf, size_t len)
{
	// disco first: its 6-byte magic is the most distinctive.
	if (len >= 6 && memcmp(buf, kDiscoMagic, 6) == 0)
		return PKT_DISCO;

	// STUN: the top two bits of a STUN message are 0 and the magic cookie sits
	// at offset 4. WireGuard transport packets have a small type byte (1..4) in
	// byte 0 and won't carry the cookie, so this stays unambiguous.
	if (len >= 20 && (buf[0] & 0xc0) == 0
			&& memcmp(buf + 4, kStunCookie, 4) == 0) {
		return PKT_STUN;
	}

	return PKT_WIREGUARD;
}

}	// namespace ts
