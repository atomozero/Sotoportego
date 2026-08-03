/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSHttp2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>


namespace ts {

// The HTTP/2 client connection preface (RFC 7540 §3.5).
static const char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// The early payload the control server sends before HTTP/2 begins.
static const uint8 kEarlyMagic[5] = { 0xff, 0xff, 0xff, 'T', 'S' };


Http2Conn::Http2Conn()
	:
	fConn(NULL),
	fLastError(""),
	fNextStreamId(1),
	fReqStream(0),
	fReqEnded(true),
	fBufOff(0),
	fBufLen(0)
{
}


void
Http2Conn::Init(ControlConn* conn)
{
	fConn = conn;
	fNextStreamId = 1;
	fReqStream = 0;
	fReqEnded = true;
	fBufOff = 0;
	fBufLen = 0;
}


status_t
Http2Conn::_Fill(size_t need)
{
	if (need > sizeof(fBuf))
		return B_BAD_VALUE;

	while (fBufLen - fBufOff < need) {
		// Compact to the front if the tail can't hold another max record.
		if (fBufOff > 0
				&& fBufLen + kH2MaxFramePayload > sizeof(fBuf)) {
			size_t live = fBufLen - fBufOff;
			memmove(fBuf, fBuf + fBufOff, live);
			fBufOff = 0;
			fBufLen = live;
		}

		ssize_t n = fConn->ReadRecord(fBuf + fBufLen, sizeof(fBuf) - fBufLen);
		if (n <= 0) {
			fLastError = "record stream ended while reading HTTP/2";
			return B_IO_ERROR;
		}
		fBufLen += (size_t)n;
	}
	return B_OK;
}


status_t
Http2Conn::_ReadRaw(uint8* dst, size_t n)
{
	status_t result = _Fill(n);
	if (result != B_OK)
		return result;
	memcpy(dst, fBuf + fBufOff, n);
	fBufOff += n;
	return B_OK;
}


status_t
Http2Conn::WriteFrame(uint8 type, uint8 flags, uint32 streamId,
	const uint8* payload, size_t len)
{
	if (fConn == NULL)
		return B_NO_INIT;
	if (len > 0xffffff)
		return B_BAD_VALUE;

	uint8 frame[kH2FrameHeaderLen + kH2MaxFramePayload];
	if (len > kH2MaxFramePayload)
		return B_BAD_VALUE;

	frame[0] = (uint8)(len >> 16);
	frame[1] = (uint8)(len >> 8);
	frame[2] = (uint8)(len & 0xff);
	frame[3] = type;
	frame[4] = flags;
	frame[5] = (uint8)((streamId >> 24) & 0x7f);
	frame[6] = (uint8)(streamId >> 16);
	frame[7] = (uint8)(streamId >> 8);
	frame[8] = (uint8)(streamId & 0xff);
	if (len > 0 && payload != NULL)
		memcpy(frame + kH2FrameHeaderLen, payload, len);

	return fConn->WriteMessage(frame, kH2FrameHeaderLen + len);
}


status_t
Http2Conn::ReadFrame(uint8* outType, uint8* outFlags, uint32* outStreamId,
	uint8* payload, size_t payloadCap, size_t* outLen)
{
	uint8 hdr[kH2FrameHeaderLen];
	status_t result = _ReadRaw(hdr, kH2FrameHeaderLen);
	if (result != B_OK)
		return result;

	size_t len = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | (size_t)hdr[2];
	uint8 type = hdr[3];
	uint8 flags = hdr[4];
	uint32 streamId = (((uint32)hdr[5] << 24) | ((uint32)hdr[6] << 16)
		| ((uint32)hdr[7] << 8) | (uint32)hdr[8]) & 0x7fffffff;

	if (len > payloadCap) {
		fLastError.SetToFormat("HTTP/2 frame (%zu) exceeds buffer", len);
		return B_ERROR;
	}
	if (len > 0) {
		result = _ReadRaw(payload, len);
		if (result != B_OK)
			return result;
	}

	if (outType != NULL) *outType = type;
	if (outFlags != NULL) *outFlags = flags;
	if (outStreamId != NULL) *outStreamId = streamId;
	if (outLen != NULL) *outLen = len;
	return B_OK;
}


status_t
Http2Conn::BeginRequest(const char* method, const char* scheme,
	const char* authority, const char* path, const char* contentType,
	const uint8* body, size_t bodyLen, int* outStatus)
{
	if (fConn == NULL)
		return B_NO_INIT;

	uint32 streamId = fNextStreamId;
	fNextStreamId += 2;
	fReqStream = streamId;
	fReqEnded = false;

	// Build the HPACK header block: pseudo-headers first, then content headers.
	std::vector<uint8> headers;
	HpackEncoder::AddHeader(headers, ":method", method);
	HpackEncoder::AddHeader(headers, ":scheme", scheme);
	HpackEncoder::AddHeader(headers, ":path", path);
	HpackEncoder::AddHeader(headers, ":authority", authority);
	if (bodyLen > 0) {
		if (contentType != NULL)
			HpackEncoder::AddHeader(headers, "content-type", contentType);
		char clen[24];
		snprintf(clen, sizeof(clen), "%zu", bodyLen);
		HpackEncoder::AddHeader(headers, "content-length", clen);
	}

	uint8 headersFlags = H2_FLAG_END_HEADERS
		| (bodyLen > 0 ? 0 : H2_FLAG_END_STREAM);
	status_t result = WriteFrame(H2_HEADERS, headersFlags, streamId,
		headers.data(), headers.size());
	if (result != B_OK)
		return result;

	if (bodyLen > 0) {
		result = WriteFrame(H2_DATA, H2_FLAG_END_STREAM, streamId, body,
			bodyLen);
		if (result != B_OK)
			return result;
	}

	// Read up to and including the response HEADERS block (decoding :status);
	// do not consume any DATA -- that's ReadBody's job.
	std::vector<uint8> headerBlock;
	int status = 0;
	uint8 payload[kH2MaxFramePayload];

	for (int frames = 0; frames < 100000; frames++) {
		uint8 type = 0, flags = 0;
		uint32 stream = 0;
		size_t len = 0;
		result = ReadFrame(&type, &flags, &stream, payload, sizeof(payload),
			&len);
		if (result != B_OK)
			return result;

		if (type == H2_SETTINGS) {
			if ((flags & H2_FLAG_ACK) == 0)
				WriteFrame(H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
			continue;
		}
		if (type == H2_PING) {
			if ((flags & H2_FLAG_ACK) == 0)
				WriteFrame(H2_PING, H2_FLAG_ACK, 0, payload, len);
			continue;
		}
		if (type == H2_GOAWAY) {
			fLastError = "server sent GOAWAY";
			return B_ERROR;
		}
		if (type == H2_RST_STREAM && stream == streamId) {
			fLastError = "server reset the request stream";
			return B_ERROR;
		}
		if ((type == H2_HEADERS || type == H2_CONTINUATION)
				&& stream == streamId) {
			size_t off = 0;
			size_t end = len;
			if (type == H2_HEADERS) {
				if ((flags & 0x08) != 0 && off < end)	// PADDED
					end -= payload[off++];
				if ((flags & 0x20) != 0)				// PRIORITY
					off += 5;
			}
			if (off <= end && end <= len)
				headerBlock.insert(headerBlock.end(), payload + off,
					payload + end);
			if ((flags & H2_FLAG_END_STREAM) != 0)
				fReqEnded = true;
			if ((flags & H2_FLAG_END_HEADERS) != 0) {
				std::vector<HpackHeader> hdrs;
				if (fDecoder.Decode(headerBlock.data(), headerBlock.size(),
						hdrs) == B_OK) {
					for (size_t i = 0; i < hdrs.size(); i++) {
						if (hdrs[i].name == ":status")
							status = atoi(hdrs[i].value.String());
					}
				}
				if (outStatus != NULL)
					*outStatus = status;
				return B_OK;
			}
		}
		// A stray DATA frame before HEADERS shouldn't happen; ignore.
	}
	fLastError = "no response HEADERS";
	return B_ERROR;
}


status_t
Http2Conn::ReadBody(uint8* buf, size_t cap, size_t* outLen)
{
	if (outLen != NULL)
		*outLen = 0;
	if (fReqEnded)
		return B_OK;	// end of stream
	if (cap < kH2MaxFramePayload)
		return B_BAD_VALUE;

	uint8 payload[kH2MaxFramePayload];
	for (int frames = 0; frames < 100000; frames++) {
		uint8 type = 0, flags = 0;
		uint32 stream = 0;
		size_t len = 0;
		status_t result = ReadFrame(&type, &flags, &stream, payload,
			sizeof(payload), &len);
		if (result != B_OK)
			return result;

		if (type == H2_SETTINGS) {
			if ((flags & H2_FLAG_ACK) == 0)
				WriteFrame(H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
			continue;
		}
		if (type == H2_PING) {
			if ((flags & H2_FLAG_ACK) == 0)
				WriteFrame(H2_PING, H2_FLAG_ACK, 0, payload, len);
			continue;
		}
		if (type == H2_GOAWAY) {
			fLastError = "server sent GOAWAY";
			return B_ERROR;
		}
		if (type == H2_RST_STREAM && stream == fReqStream) {
			fLastError = "server reset the stream";
			return B_ERROR;
		}
		if (type == H2_DATA && stream == fReqStream) {
			size_t off = 0;
			size_t end = len;
			if ((flags & 0x08) != 0 && off < end)	// PADDED
				end -= payload[off++];
			size_t n = (end > off) ? end - off : 0;
			if (n > 0)
				memcpy(buf, payload + off, n);
			// Replenish stream + connection flow-control windows.
			if (len > 0) {
				uint8 inc[4] = { (uint8)(len >> 24), (uint8)(len >> 16),
					(uint8)(len >> 8), (uint8)len };
				WriteFrame(H2_WINDOW_UPDATE, 0, fReqStream, inc, 4);
				WriteFrame(H2_WINDOW_UPDATE, 0, 0, inc, 4);
			}
			if ((flags & H2_FLAG_END_STREAM) != 0)
				fReqEnded = true;
			if (outLen != NULL)
				*outLen = n;
			return B_OK;
		}
		if (type == H2_HEADERS && stream == fReqStream
				&& (flags & H2_FLAG_END_STREAM) != 0) {
			fReqEnded = true;	// trailers, end of stream
			return B_OK;
		}
	}
	fLastError = "body read exceeded frame budget";
	return B_ERROR;
}


status_t
Http2Conn::Request(const char* method, const char* scheme,
	const char* authority, const char* path, const char* contentType,
	const uint8* body, size_t bodyLen, int* outStatus, BString* outRespBody)
{
	int status = 0;
	status_t result = BeginRequest(method, scheme, authority, path,
		contentType, body, bodyLen, &status);
	if (result != B_OK)
		return result;

	BString respBody;
	uint8 chunk[kH2MaxFramePayload];
	for (;;) {
		size_t n = 0;
		result = ReadBody(chunk, sizeof(chunk), &n);
		if (result != B_OK)
			return result;
		if (n > 0)
			respBody.Append((const char*)chunk, n);
		if (fReqEnded)
			break;
	}

	if (outStatus != NULL)
		*outStatus = status;
	if (outRespBody != NULL)
		*outRespBody = respBody;
	return B_OK;
}


status_t
Http2Conn::Bootstrap(BString* outEarlyJson)
{
	if (fConn == NULL)
		return B_NO_INIT;

	// 1) Early payload: magic, BE32 length, JSON.
	uint8 magic[5];
	status_t result = _ReadRaw(magic, sizeof(magic));
	if (result != B_OK)
		return result;
	if (memcmp(magic, kEarlyMagic, sizeof(magic)) != 0) {
		fLastError = "missing early-payload magic";
		return B_ERROR;
	}
	uint8 lenBuf[4];
	result = _ReadRaw(lenBuf, 4);
	if (result != B_OK)
		return result;
	uint32 jsonLen = ((uint32)lenBuf[0] << 24) | ((uint32)lenBuf[1] << 16)
		| ((uint32)lenBuf[2] << 8) | (uint32)lenBuf[3];
	if (jsonLen > 8192) {
		fLastError = "early-payload JSON too large";
		return B_ERROR;
	}
	uint8 json[8192];
	result = _ReadRaw(json, jsonLen);
	if (result != B_OK)
		return result;
	if (outEarlyJson != NULL)
		outEarlyJson->SetTo((const char*)json, jsonLen);

	// 2) Send the client preface + our (empty) SETTINGS.
	result = fConn->WriteMessage(kH2Preface, sizeof(kH2Preface) - 1);
	if (result != B_OK) {
		fLastError = "failed to send HTTP/2 preface";
		return result;
	}
	result = WriteFrame(H2_SETTINGS, 0, 0, NULL, 0);
	if (result != B_OK)
		return result;

	// 3) Exchange SETTINGS: ACK the server's, observe the ACK of ours.
	bool ourSettingsAcked = false;
	bool theirSettingsAcked = false;
	for (int i = 0; i < 32 && !(ourSettingsAcked && theirSettingsAcked); i++) {
		uint8 type = 0, flags = 0;
		uint32 stream = 0;
		uint8 payload[kH2MaxFramePayload];
		size_t len = 0;
		result = ReadFrame(&type, &flags, &stream, payload, sizeof(payload),
			&len);
		if (result != B_OK)
			return result;

		if (type == H2_SETTINGS) {
			if ((flags & H2_FLAG_ACK) != 0) {
				ourSettingsAcked = true;
			} else {
				// ACK the server's settings.
				result = WriteFrame(H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
				if (result != B_OK)
					return result;
				theirSettingsAcked = true;
			}
		} else if (type == H2_GOAWAY) {
			fLastError = "server sent GOAWAY during HTTP/2 handshake";
			return B_ERROR;
		}
		// WINDOW_UPDATE and anything else at this stage is ignored.
	}

	if (!(ourSettingsAcked && theirSettingsAcked)) {
		fLastError = "HTTP/2 SETTINGS handshake did not complete";
		return B_ERROR;
	}
	return B_OK;
}

}	// namespace ts
