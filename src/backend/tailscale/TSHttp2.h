/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_HTTP2_H
#define TS_HTTP2_H


#include <stddef.h>
#include <sys/types.h>

#include <String.h>
#include <SupportDefs.h>

#include "TSControlConn.h"
#include "TSHpack.h"


// A minimal HTTP/2 client that runs over the ts2021 encrypted record stream
// (ControlConn). Tailscale's control RPCs -- register, map, set-dns, etc. -- are
// HTTP requests carried over HTTP/2 on the Noise connection, so a small h2 core
// is required. This layer owns:
//
//   * consuming the post-handshake "early payload" the server sends before
//     HTTP/2 begins (magic "\xff\xff\xffTS" + BE32 length + a JSON
//     tailcfg.EarlyNoise carrying the nodeKeyChallenge);
//   * reading/writing HTTP/2 frames, reassembling them from record boundaries
//     (records and frames are not aligned);
//   * the connection bootstrap: send the client preface + SETTINGS, ACK the
//     server's SETTINGS and observe the ACK of ours.
//
// HPACK header (de)compression and the request/response helpers layer on top in
// a following change; this is the framed transport underneath them.
namespace ts {

// HTTP/2 frame types (RFC 7540 §6).
enum Http2FrameType {
	H2_DATA			= 0x0,
	H2_HEADERS		= 0x1,
	H2_PRIORITY		= 0x2,
	H2_RST_STREAM	= 0x3,
	H2_SETTINGS		= 0x4,
	H2_PUSH_PROMISE	= 0x5,
	H2_PING			= 0x6,
	H2_GOAWAY		= 0x7,
	H2_WINDOW_UPDATE = 0x8,
	H2_CONTINUATION	= 0x9
};

// Frame flags we use.
enum Http2Flags {
	H2_FLAG_ACK			= 0x01,	// SETTINGS/PING ack
	H2_FLAG_END_STREAM	= 0x01,	// DATA/HEADERS
	H2_FLAG_END_HEADERS	= 0x04	// HEADERS/CONTINUATION
};

static const size_t kH2FrameHeaderLen	= 9;
static const size_t kH2MaxFramePayload	= 16384;	// our advertised max


class Http2Conn {
public:
								Http2Conn();

			// Bind to a handshaked, record-encrypted control connection.
			void				Init(ControlConn* conn);

			// Consume the early payload and run the HTTP/2 connection handshake
			// (preface + SETTINGS exchange). On success `outEarlyJson`, if
			// non-NULL, receives the tailcfg.EarlyNoise JSON (has the
			// nodeKeyChallenge). Returns B_OK once both SETTINGS are ACKed.
			status_t			Bootstrap(BString* outEarlyJson);

			// Perform one request/response exchange on a fresh stream: send
			// HEADERS (HPACK-encoded pseudo-headers + content-type/length) and,
			// if `bodyLen` > 0, a DATA frame, then read the response, decoding
			// `:status` and collecting the response body. Control frames
			// (SETTINGS/PING/WINDOW_UPDATE) that arrive meanwhile are handled.
			// Returns B_OK once the response stream ends.
			status_t			Request(const char* method, const char* scheme,
									const char* authority, const char* path,
									const char* contentType, const uint8* body,
									size_t bodyLen, int* outStatus,
									BString* outRespBody);

			// Streaming variant for long-poll endpoints (e.g. /machine/map).
			// BeginRequest sends the request and reads up to and including the
			// response HEADERS, returning `:status`; the response body is then
			// pulled incrementally with ReadBody (one DATA frame's payload per
			// call, `cap` must be >= kH2MaxFramePayload), which returns
			// *outLen == 0 at end of stream.
			status_t			BeginRequest(const char* method,
									const char* scheme, const char* authority,
									const char* path, const char* contentType,
									const uint8* body, size_t bodyLen,
									int* outStatus);
			status_t			ReadBody(uint8* buf, size_t cap,
									size_t* outLen);

			// Write one HTTP/2 frame.
			status_t			WriteFrame(uint8 type, uint8 flags,
									uint32 streamId, const uint8* payload,
									size_t len);
			// Read one HTTP/2 frame into `payload` (>= its length). Fills the
			// out-params; returns B_OK, or an error on EOF / oversize.
			status_t			ReadFrame(uint8* outType, uint8* outFlags,
									uint32* outStreamId, uint8* payload,
									size_t payloadCap, size_t* outLen);

			const char*			LastError() const { return fLastError.String(); }

private:
			status_t			_ReadRaw(uint8* dst, size_t n);
			status_t			_Fill(size_t need);

			ControlConn*		fConn;
			BString				fLastError;

			// Client streams use odd IDs, incrementing per request.
			uint32				fNextStreamId;
			// In-flight streaming request state (BeginRequest/ReadBody).
			uint32				fReqStream;
			bool				fReqEnded;
			// Response HPACK decoder: its dynamic table persists for the life of
			// the connection, across all responses.
			HpackDecoder		fDecoder;

			// Reassembly buffer: valid bytes live in [fBufOff, fBufLen).
			uint8				fBuf[65536];
			size_t				fBufOff;
			size_t				fBufLen;
};

}	// namespace ts


#endif	// TS_HTTP2_H
