/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSDisco.h"

#include <stdio.h>
#include <string.h>

#include "NaClBox.h"
#include "WireGuardCrypto.h"		// RandomBytes


namespace ts {

static const uint8 kDiscoMagic[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };


// Encode a v4 address "a.b.c.d" as the 16-byte v4-mapped IPv6 form
// (::ffff:a.b.c.d) Tailscale uses on the wire. Returns false on a bad address.
static bool
encode_ipv4_mapped(const char* ip, uint8 out[16])
{
	unsigned a, b, c, d;
	if (ip == NULL || sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return false;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return false;
	memset(out, 0, 10);
	out[10] = 0xff;
	out[11] = 0xff;
	out[12] = (uint8)a;
	out[13] = (uint8)b;
	out[14] = (uint8)c;
	out[15] = (uint8)d;
	return true;
}


static void
decode_ipv4_mapped(const uint8 in[16], BString& out)
{
	// v4-mapped ::ffff:a.b.c.d -> "a.b.c.d"; otherwise render the raw v4 tail.
	char buf[16];
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u", in[12], in[13], in[14], in[15]);
	out = buf;
}


size_t
EncodePing(uint8* out, const uint8 txid[12], const uint8* nodeKey)
{
	out[0] = (uint8)DISCO_PING;
	out[1] = 0;	// version
	memcpy(out + 2, txid, 12);
	if (nodeKey != NULL) {
		memcpy(out + 14, nodeKey, 32);
		return 46;
	}
	return 14;
}


size_t
EncodePong(uint8* out, const uint8 txid[12], const char* srcIP, uint16 srcPort)
{
	out[0] = (uint8)DISCO_PONG;
	out[1] = 0;
	memcpy(out + 2, txid, 12);
	uint8 ip16[16];
	if (!encode_ipv4_mapped(srcIP, ip16))
		memset(ip16, 0, 16);
	memcpy(out + 14, ip16, 16);
	out[30] = (uint8)(srcPort >> 8);
	out[31] = (uint8)(srcPort & 0xff);
	return 32;
}


uint8
DiscoMessageType(const uint8* msg, size_t len)
{
	if (msg == NULL || len < kDiscoMsgHeaderLen)
		return 0;
	return msg[0];
}


bool
DecodePing(const uint8* msg, size_t len, DiscoPing& out)
{
	if (len < kDiscoMsgHeaderLen + kDiscoTxIDLen || msg[0] != DISCO_PING)
		return false;
	memcpy(out.txid, msg + 2, 12);
	if (len >= 46) {
		memcpy(out.nodeKey, msg + 14, 32);
		out.hasNodeKey = true;
	} else {
		out.hasNodeKey = false;
	}
	return true;
}


bool
DecodePong(const uint8* msg, size_t len, DiscoPong& out)
{
	if (len < kDiscoMsgHeaderLen + kDiscoTxIDLen + 16 + 2
			|| msg[0] != DISCO_PONG)
		return false;
	memcpy(out.txid, msg + 2, 12);
	decode_ipv4_mapped(msg + 14, out.srcIP);
	out.srcPort = (uint16)(((uint16)msg[30] << 8) | msg[31]);
	return true;
}


ssize_t
DiscoSeal(uint8* out, size_t outCap, const uint8 senderDiscoPub[32],
	const uint8 senderDiscoPriv[32], const uint8 peerDiscoPub[32],
	const uint8* payload, size_t payloadLen)
{
	size_t total = kDiscoHeaderOff + payloadLen + 16;	// +16 box tag
	if (outCap < total)
		return -1;

	memcpy(out, kDiscoMagic, kDiscoMagicLen);
	memcpy(out + kDiscoMagicLen, senderDiscoPub, 32);
	uint8* noncePtr = out + kDiscoMagicLen + 32;
	wg::RandomBytes(noncePtr, kDiscoNonceLen);

	if (!BoxSeal(out + kDiscoHeaderOff, payload, payloadLen, noncePtr,
			peerDiscoPub, senderDiscoPriv))
		return -1;

	return (ssize_t)total;
}


ssize_t
DiscoOpen(const uint8* packet, size_t len, const uint8 myDiscoPriv[32],
	uint8 outSenderPub[32], uint8* outPayload, size_t outCap)
{
	if (len < kDiscoHeaderOff + 16)
		return -1;
	if (memcmp(packet, kDiscoMagic, kDiscoMagicLen) != 0)
		return -1;

	memcpy(outSenderPub, packet + kDiscoMagicLen, 32);
	const uint8* noncePtr = packet + kDiscoMagicLen + 32;
	const uint8* cipher = packet + kDiscoHeaderOff;
	size_t cipherLen = len - kDiscoHeaderOff;
	size_t plainLen = cipherLen - 16;
	if (plainLen > outCap)
		return -1;

	if (!BoxOpen(outPayload, cipher, cipherLen, noncePtr, outSenderPub,
			myDiscoPriv))
		return -1;

	return (ssize_t)plainLen;
}

}	// namespace ts
