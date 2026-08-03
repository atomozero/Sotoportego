/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_MAP_H
#define TS_MAP_H


#include <String.h>
#include <SupportDefs.h>

#include <vector>

#include "TSHttp2.h"


// The network-map exchange. A `MapRequest` is POSTed to /machine/map over the
// ts2021 HTTP/2 channel; the server replies with a stream of `MapResponse`
// messages, each framed as a 4-byte little-endian length followed by that many
// bytes of (here, uncompressed) JSON. The first message is the full netmap
// snapshot; further messages are deltas.
//
// MapStream owns the request + the stream de-framer (it buffers HTTP/2 DATA
// across message boundaries). Parsing a MapResponse into a TSNetmap (self
// address, peers, DERP map, DNS) lands in the following change; for now
// ReadMessage returns the raw JSON of each message so the transport + framing
// can be validated end to end.
namespace ts {

class MapStream {
public:
								MapStream();

			// Build the JSON MapRequest for `nodePub` and start the streamed
			// response on `h2` (kept open for ReadMessage). Fills `outStatus`
			// with the HTTP status. Returns B_OK if the request was sent and the
			// response headers were read.
			status_t			Begin(Http2Conn& h2, const char* host,
									uint16 version, const uint8 nodePub[32],
									const char* hostname, int* outStatus);

			// Read the next length-prefixed MapResponse JSON message into
			// `outJson`. Returns B_OK with a message, B_ENTRY_NOT_FOUND at clean
			// end of stream, or an error. Blocks until a full message arrives
			// (bounded by the socket read timeout).
			status_t			ReadMessage(BString& outJson);

private:
			status_t			_FillAtLeast(size_t need, bool& outEof);

			Http2Conn*			fHttp2;
			std::vector<uint8>	fAcc;		// undelivered stream bytes
			size_t				fAccOff;	// consumed prefix of fAcc
};

}	// namespace ts


#endif	// TS_MAP_H
