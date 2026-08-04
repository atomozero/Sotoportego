/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSMap.h"

#include <string.h>

#include "TSIdentity.h"		// ToHex


namespace ts {

// A single MapResponse is bounded well under this; reject anything larger as a
// framing error rather than trying to allocate it.
static const uint32 kMaxMapMessage = 32 * 1024 * 1024;


MapStream::MapStream()
	:
	fHttp2(NULL),
	fAccOff(0)
{
}


status_t
MapStream::Begin(Http2Conn& h2, const char* host, uint16 version,
	const uint8 nodePub[32], const uint8 discoPub[32], const char* hostname,
	const char* endpointsJson, int* outStatus)
{
	fHttp2 = &h2;
	fAcc.clear();
	fAccOff = 0;

	BString nodeHex = TSIdentity::ToHex(nodePub, 32);
	BString discoHex = TSIdentity::ToHex(discoPub, 32);

	// Minimal streaming MapRequest. Compress is omitted (""), so responses are
	// plain JSON; Stream:true asks for the snapshot-then-deltas long poll.
	// DiscoKey is essential: control propagates it to peers so they can open
	// (and answer) our NaCl-boxed disco pings -- without it no direct path can
	// ever form. Endpoints let peers reach us directly too.
	BString body;
	body << "{";
	body << "\"Version\":" << (int32)version << ",";
	body << "\"NodeKey\":\"nodekey:" << nodeHex << "\",";
	body << "\"DiscoKey\":\"discokey:" << discoHex << "\",";
	body << "\"Stream\":true,";
	body << "\"OmitPeers\":false,";
	body << "\"Endpoints\":["
		<< (endpointsJson != NULL ? endpointsJson : "") << "],";
	body << "\"Hostinfo\":{";
	body << "\"IPNVersion\":\"0.1.0\",";
	body << "\"Hostname\":\"" << (hostname != NULL ? hostname : "haiku") << "\",";
	body << "\"OS\":\"haiku\"";
	body << "}";
	body << "}";

	return fHttp2->BeginRequest("POST", "https", host, "/machine/map",
		"application/json", (const uint8*)body.String(), body.Length(),
		outStatus);
}


status_t
MapStream::_FillAtLeast(size_t need, bool& outEof)
{
	outEof = false;
	uint8 chunk[kH2MaxFramePayload];
	while (fAcc.size() - fAccOff < need) {
		size_t n = 0;
		status_t result = fHttp2->ReadBody(chunk, sizeof(chunk), &n);
		if (result != B_OK)
			return result;
		if (n == 0) {
			// End of stream (or an empty DATA frame). If ReadBody reports the
			// stream ended with nothing buffered, that's a clean EOF.
			outEof = true;
			return B_OK;
		}
		// Compact consumed prefix occasionally to bound memory.
		if (fAccOff > 0 && fAccOff == fAcc.size()) {
			fAcc.clear();
			fAccOff = 0;
		}
		fAcc.insert(fAcc.end(), chunk, chunk + n);
	}
	return B_OK;
}


status_t
MapStream::ReadMessage(BString& outJson)
{
	if (fHttp2 == NULL)
		return B_NO_INIT;

	// 4-byte little-endian length prefix.
	bool eof = false;
	status_t result = _FillAtLeast(4, eof);
	if (result != B_OK)
		return result;
	if (eof && fAcc.size() - fAccOff < 4)
		return B_ENTRY_NOT_FOUND;	// clean end of stream

	const uint8* p = fAcc.data() + fAccOff;
	uint32 msgLen = (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
	if (msgLen > kMaxMapMessage)
		return B_BAD_DATA;

	result = _FillAtLeast(4 + msgLen, eof);
	if (result != B_OK)
		return result;
	if (fAcc.size() - fAccOff < 4 + msgLen)
		return B_IO_ERROR;	// stream ended mid-message

	p = fAcc.data() + fAccOff;
	outJson.SetTo((const char*)(p + 4), msgLen);
	fAccOff += 4 + msgLen;

	if (fAccOff == fAcc.size()) {
		fAcc.clear();
		fAccOff = 0;
	}
	return B_OK;
}

}	// namespace ts
