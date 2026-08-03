/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_REGISTER_H
#define TS_REGISTER_H


#include <String.h>
#include <SupportDefs.h>

#include "TSHttp2.h"


// Node registration against a Tailscale/Headscale control server, over the
// ts2021 HTTP/2 channel. Builds the JSON tailcfg.RegisterRequest and parses the
// RegisterResponse.
//
// Over the Noise channel the machine key is already authenticated by the
// transport, so the request is plaintext JSON POSTed to /machine/register --
// no per-request signature. Without an auth key the server answers with an
// AuthURL for interactive browser login; with a pre-auth key the node can be
// authorized non-interactively.
namespace ts {

struct RegisterResult {
	int			httpStatus;			// HTTP :status of the register response
	bool		machineAuthorized;	// node is authorized into a tailnet
	bool		nodeKeyExpired;		// the node key has expired, re-key needed
	BString		authURL;			// browser login URL (interactive flow)
	BString		error;				// server-reported error, if any
};


// Build and send a RegisterRequest for `nodePub` (our 32-byte node public key)
// with the given hostname; if `authKey` is non-empty it is sent as a pre-auth
// key. `host` is the :authority for the request. The Http2Conn must already be
// bootstrapped. Fills `out`. Returns B_OK if a response was received and parsed
// (even one carrying a server Error), or a transport error otherwise.
status_t Register(Http2Conn& h2, const char* host, uint16 version,
			const uint8 nodePub[32], const char* hostname, const char* authKey,
			RegisterResult& out);

}	// namespace ts


#endif	// TS_REGISTER_H
