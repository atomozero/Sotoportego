/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSStun.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "WireGuardCrypto.h"		// RandomBytes


namespace ts {

static const uint16 kBindingRequest	= 0x0001;
static const uint16 kBindingSuccess	= 0x0101;
static const uint16 kAttrMappedAddr		= 0x0001;
static const uint16 kAttrXorMappedAddr	= 0x0020;


static uint16
rd16(const uint8* p)
{
	return (uint16)(((uint16)p[0] << 8) | p[1]);
}


void
StunBuildRequest(uint8 out[20], uint8 txId[12])
{
	wg::RandomBytes(txId, 12);
	out[0] = (uint8)(kBindingRequest >> 8);
	out[1] = (uint8)(kBindingRequest & 0xff);
	out[2] = 0;	// message length = 0 (no attributes)
	out[3] = 0;
	out[4] = (uint8)(kStunMagicCookie >> 24);
	out[5] = (uint8)(kStunMagicCookie >> 16);
	out[6] = (uint8)(kStunMagicCookie >> 8);
	out[7] = (uint8)(kStunMagicCookie & 0xff);
	memcpy(out + 8, txId, 12);
}


bool
StunParseResponse(const uint8* buf, size_t len, const uint8 txId[12],
	BString& outIP, uint16& outPort)
{
	if (buf == NULL || len < kStunHeaderLen)
		return false;
	if (rd16(buf) != kBindingSuccess)
		return false;
	// Verify magic cookie and transaction id.
	if (buf[4] != (uint8)(kStunMagicCookie >> 24)
			|| buf[5] != (uint8)(kStunMagicCookie >> 16)
			|| buf[6] != (uint8)(kStunMagicCookie >> 8)
			|| buf[7] != (uint8)(kStunMagicCookie & 0xff))
		return false;
	if (memcmp(buf + 8, txId, 12) != 0)
		return false;

	uint16 msgLen = rd16(buf + 2);
	if (kStunHeaderLen + msgLen > len)
		msgLen = (uint16)(len - kStunHeaderLen);

	// Walk the attributes.
	size_t off = kStunHeaderLen;
	size_t end = kStunHeaderLen + msgLen;
	while (off + 4 <= end) {
		uint16 attrType = rd16(buf + off);
		uint16 attrLen = rd16(buf + off + 2);
		size_t val = off + 4;
		if (val + attrLen > end)
			break;

		if ((attrType == kAttrXorMappedAddr || attrType == kAttrMappedAddr)
				&& attrLen >= 8) {
			// [reserved][family][port(2)][address(4 for IPv4)]
			uint8 family = buf[val + 1];
			if (family == 0x01) {	// IPv4
				uint16 port = rd16(buf + val + 2);
				uint8 addr[4];
				memcpy(addr, buf + val + 4, 4);
				if (attrType == kAttrXorMappedAddr) {
					port ^= (uint16)(kStunMagicCookie >> 16);
					addr[0] ^= (uint8)(kStunMagicCookie >> 24);
					addr[1] ^= (uint8)(kStunMagicCookie >> 16);
					addr[2] ^= (uint8)(kStunMagicCookie >> 8);
					addr[3] ^= (uint8)(kStunMagicCookie & 0xff);
				}
				char ip[16];
				snprintf(ip, sizeof(ip), "%u.%u.%u.%u", addr[0], addr[1],
					addr[2], addr[3]);
				outIP = ip;
				outPort = port;
				return true;
			}
		}

		// Attributes are padded to 4-byte boundaries.
		off = val + attrLen;
		if ((attrLen & 3) != 0)
			off += 4 - (attrLen & 3);
	}
	return false;
}


status_t
StunQuery(const char* host, uint16 port, BString& outIP, uint16& outPort)
{
	if (host == NULL)
		return B_BAD_VALUE;

	char portStr[8];
	snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;			// STUN underlay is v4 here
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo* res = NULL;
	if (getaddrinfo(host, portStr, &hints, &res) != 0 || res == NULL)
		return B_NAME_NOT_FOUND;

	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0) {
		freeaddrinfo(res);
		return B_ERROR;
	}
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	uint8 req[20];
	uint8 txId[12];
	StunBuildRequest(req, txId);

	status_t result = B_ERROR;
	if (sendto(sock, req, sizeof(req), 0, res->ai_addr, res->ai_addrlen)
			== (ssize_t)sizeof(req)) {
		uint8 buf[512];
		ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
		if (n > 0 && StunParseResponse(buf, (size_t)n, txId, outIP, outPort))
			result = B_OK;
		else if (n <= 0)
			result = B_TIMED_OUT;
	}

	close(sock);
	freeaddrinfo(res);
	return result;
}

}	// namespace ts
