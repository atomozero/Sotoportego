/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONTROL_SESSION_H
#define TS_CONTROL_SESSION_H


#include <String.h>
#include <SupportDefs.h>

#include "TSHttp2.h"
#include "TSRegister.h"


// Drives the ts2021 control flow: the Noise handshake, the encrypted record
// stream, the HTTP/2 connection, node registration, and the followup poll.
//
// The control server closes the Noise connection after each register response,
// so a single connection can't be reused across register → followup → map.
// ControlSession therefore (re)establishes a fresh handshake + HTTP/2 connection
// for every control request (Connect, each PollAuthorized, and Establish before
// the map). The connection objects live on the heap so they can be torn down and
// rebuilt cleanly; the machine keypair + endpoint are captured on Connect so the
// later calls can re-handshake without the caller re-passing them.
namespace ts {

class ControlClient;
class ControlConn;

class ControlSession {
public:
								ControlSession();
								~ControlSession();

			// Establish a fresh connection and send the initial RegisterRequest
			// for the node key. `insecure` disables TLS verification (self-hosted
			// control). On B_OK `out` holds the parsed response.
			status_t			Connect(const char* host, uint16 port,
									bool insecure, uint16 version,
									const uint8 machinePriv[32],
									const uint8 machinePub[32],
									const uint8 nodePub[32],
									const char* hostname, const char* authKey,
									RegisterResult& out);

			// Re-establish a fresh connection and re-issue the register as a
			// followup on `authURL`; the server long-polls until the browser
			// login completes (or it times out). Reuses the machine keypair /
			// endpoint captured by Connect.
			status_t			PollAuthorized(const char* host, uint16 version,
									const uint8 nodePub[32], const char* hostname,
									const char* authURL, RegisterResult& out);

			// Open a fresh handshake + HTTP/2 connection (no request), so the
			// caller can drive the map long-poll on Http2(). Returns B_OK.
			status_t			Establish();

			const BString&		EarlyJson() const { return fEarlyJson; }
			Http2Conn&			Http2() { return fHttp2; }
			const char*			LastError() const { return fLastError.String(); }

private:
			// Tear down any live connection and build a fresh
			// handshake → record stream → HTTP/2 into the members, using the
			// captured endpoint + machine keypair.
			status_t			_Establish();

			BString				fHost;
			uint16				fPort;
			bool				fInsecure;
			uint16				fVersion;
			uint8				fMachinePriv[32];
			uint8				fMachinePub[32];
			bool				fHaveParams;

			ControlClient*		fClient;	// heap so we can rebuild per request
			ControlConn*		fConn;
			Http2Conn			fHttp2;
			BString				fEarlyJson;
			BString				fLastError;
};

}	// namespace ts


#endif	// TS_CONTROL_SESSION_H
