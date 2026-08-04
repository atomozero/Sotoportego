/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSDerp.h"

#include <stdio.h>
#include <string.h>

#include "NaClBox.h"
#include "WireGuardCrypto.h"		// RandomBytes


namespace ts {

// frameServerKey magic: "DERP🔑" = 44 45 52 50 f0 9f 94 91.
static const uint8 kDerpMagic[8] = {
	0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91
};

// The client is willing to receive frames up to this size.
static const size_t kDerpMaxFrame = 65535;


DerpClient::DerpClient()
	:
	fLastError(""),
	fBufOff(0),
	fBufLen(0)
{
	memset(fServerKey, 0, sizeof(fServerKey));
	memset(fNodePriv, 0, sizeof(fNodePriv));
	memset(fNodePub, 0, sizeof(fNodePub));
}


DerpClient::~DerpClient()
{
	fTls.Close();
}


status_t
DerpClient::_Fill(size_t need)
{
	if (need > sizeof(fBuf))
		return B_BAD_VALUE;
	while (fBufLen - fBufOff < need) {
		if (fBufOff > 0 && fBufLen + 4096 > sizeof(fBuf)) {
			size_t live = fBufLen - fBufOff;
			memmove(fBuf, fBuf + fBufOff, live);
			fBufOff = 0;
			fBufLen = live;
		}
		ssize_t n = fTls.Read(fBuf + fBufLen, sizeof(fBuf) - fBufLen);
		if (n <= 0) {
			fLastError = "DERP connection closed";
			return B_IO_ERROR;
		}
		fBufLen += (size_t)n;
	}
	return B_OK;
}


status_t
DerpClient::_ReadRaw(uint8* dst, size_t n)
{
	status_t r = _Fill(n);
	if (r != B_OK)
		return r;
	memcpy(dst, fBuf + fBufOff, n);
	fBufOff += n;
	return B_OK;
}


status_t
DerpClient::WriteFrame(uint8 type, const uint8* payload, size_t len)
{
	uint8 hdr[5];
	hdr[0] = type;
	hdr[1] = (uint8)(len >> 24);
	hdr[2] = (uint8)(len >> 16);
	hdr[3] = (uint8)(len >> 8);
	hdr[4] = (uint8)(len & 0xff);
	if (fTls.Write(hdr, 5) != 5)
		return B_IO_ERROR;
	size_t off = 0;
	while (off < len) {
		ssize_t w = fTls.Write(payload + off, len - off);
		if (w <= 0)
			return B_IO_ERROR;
		off += (size_t)w;
	}
	return B_OK;
}


status_t
DerpClient::ReadFrame(uint8* outType, uint8* buf, size_t cap, size_t* outLen)
{
	uint8 hdr[5];
	status_t r = _ReadRaw(hdr, 5);
	if (r != B_OK)
		return r;
	uint8 type = hdr[0];
	size_t len = ((size_t)hdr[1] << 24) | ((size_t)hdr[2] << 16)
		| ((size_t)hdr[3] << 8) | (size_t)hdr[4];
	if (len > kDerpMaxFrame) {
		fLastError = "oversize DERP frame";
		return B_ERROR;
	}
	if (len > cap)
		return B_BAD_VALUE;
	if (len > 0) {
		r = _ReadRaw(buf, len);
		if (r != B_OK)
			return r;
	}
	if (outType != NULL) *outType = type;
	if (outLen != NULL) *outLen = len;
	return B_OK;
}


status_t
DerpClient::_ReadUpgrade()
{
	// Read the HTTP 101 response, keeping any framed bytes that follow in the
	// buffer for ReadFrame.
	uint8 tmp[4096];
	size_t total = 0;
	int headerEnd = -1;
	while (total < sizeof(tmp)) {
		ssize_t n = fTls.Read(tmp + total, sizeof(tmp) - total);
		if (n <= 0)
			break;
		total += (size_t)n;
		for (size_t i = 0; i + 3 < total; i++) {
			if (tmp[i] == '\r' && tmp[i + 1] == '\n'
					&& tmp[i + 2] == '\r' && tmp[i + 3] == '\n') {
				headerEnd = (int)(i + 4);
				break;
			}
		}
		if (headerEnd >= 0)
			break;
	}
	if (headerEnd < 0) {
		fLastError = "no HTTP header terminator from DERP";
		return B_ERROR;
	}
	if (memmem(tmp, headerEnd, " 101 ", 5) == NULL) {
		fLastError = "DERP upgrade not accepted (no 101)";
		return B_ERROR;
	}
	// Seed the frame buffer with post-header bytes.
	size_t leftover = total - (size_t)headerEnd;
	if (leftover > 0) {
		memcpy(fBuf, tmp + headerEnd, leftover);
		fBufLen = leftover;
	}
	return B_OK;
}


status_t
DerpClient::Connect(const char* host, uint16 port, bool insecure,
	const uint8 nodePriv[32], const uint8 nodePub[32])
{
	memcpy(fNodePriv, nodePriv, 32);
	memcpy(fNodePub, nodePub, 32);
	fBufOff = 0;
	fBufLen = 0;

	fTls.SetInsecure(insecure);
	status_t r = fTls.Connect(host, port);
	if (r != B_OK) {
		fLastError.SetToFormat("DERP TLS connect failed: %s", fTls.LastError());
		return r;
	}

	BString req;
	req.SetToFormat(
		"GET /derp HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: DERP\r\n"
		"Connection: Upgrade\r\n"
		"User-Agent: Sotoportego/0.1\r\n\r\n",
		host);
	if (fTls.Write(req.String(), req.Length()) < 0) {
		fLastError = "failed to send DERP upgrade";
		return B_IO_ERROR;
	}

	r = _ReadUpgrade();
	if (r != B_OK)
		return r;

	// frameServerKey: magic (8) + server public key (32).
	uint8 type = 0;
	uint8 payload[kDerpMaxFrame];
	size_t len = 0;
	r = ReadFrame(&type, payload, sizeof(payload), &len);
	if (r != B_OK)
		return r;
	if (type != DERP_SERVER_KEY || len < kDerpMagicLen + kDerpKeyLen
			|| memcmp(payload, kDerpMagic, kDerpMagicLen) != 0) {
		fLastError = "bad frameServerKey";
		return B_ERROR;
	}
	memcpy(fServerKey, payload + kDerpMagicLen, 32);

	// frameClientInfo: our node pub (32) + nonce (24) + NaClbox(json).
	const char* infoJson = "{\"version\":2,\"meshKey\":\"\"}";
	size_t jsonLen = strlen(infoJson);
	uint8 info[32 + 24 + 256];
	memcpy(info, fNodePub, 32);
	uint8* nonce = info + 32;
	wg::RandomBytes(nonce, 24);
	if (!BoxSeal(info + 56, (const uint8*)infoJson, jsonLen, nonce, fServerKey,
			fNodePriv)) {
		fLastError = "failed to seal clientInfo";
		return B_ERROR;
	}
	size_t infoLen = 32 + 24 + jsonLen + 16;
	r = WriteFrame(DERP_CLIENT_INFO, info, infoLen);
	if (r != B_OK)
		return r;

	return B_OK;
}


status_t
DerpClient::SendPacket(const uint8 dstKey[32], const uint8* pkt, size_t len)
{
	// frameSendPacket: 32-byte dst key + packet bytes.
	uint8 frame[32 + 4096];
	if (len > sizeof(frame) - 32)
		return B_BAD_VALUE;
	memcpy(frame, dstKey, 32);
	memcpy(frame + 32, pkt, len);
	return WriteFrame(DERP_SEND_PACKET, frame, 32 + len);
}


ssize_t
DerpClient::RecvPacket(uint8 outSrcKey[32], uint8* out, size_t cap)
{
	uint8 type = 0;
	uint8 payload[kDerpMaxFrame];
	size_t len = 0;
	status_t r = ReadFrame(&type, payload, sizeof(payload), &len);
	if (r != B_OK)
		return -1;

	if (type == DERP_RECV_PACKET) {
		if (len < 32)
			return -1;
		size_t pktLen = len - 32;
		if (pktLen > cap)
			return -1;
		memcpy(outSrcKey, payload, 32);
		memcpy(out, payload + 32, pktLen);
		return (ssize_t)pktLen;
	}
	if (type == DERP_PING) {
		// Echo the ping data back as a pong to keep the path alive.
		WriteFrame(DERP_PONG, payload, len);
		return 0;
	}
	// KeepAlive / ServerInfo / PeerGone / Health / etc: nothing to deliver.
	return 0;
}

}	// namespace ts
