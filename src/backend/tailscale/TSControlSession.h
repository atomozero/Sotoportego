/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONTROL_SESSION_H
#define TS_CONTROL_SESSION_H


#include <String.h>
#include <SupportDefs.h>

#include "TSControlClient.h"
#include "TSControlConn.h"
#include "TSHttp2.h"
#include "TSRegister.h"


// One end-to-end control session: the Noise handshake, the encrypted record
// stream, the HTTP/2 connection and the node registration, wired together so the
// backend (or a test) drives the whole ts2021 flow through a single object. It
// owns the layered pieces in dependency order so their lifetimes nest correctly,
// and keeps the HTTP/2 connection open after registration for the subsequent
// MapRequest long-poll (Phase 3).
namespace ts {

class ControlSession {
public:
								ControlSession();

			// Handshake with the machine keypair, bring up HTTP/2, and send the
			// initial RegisterRequest for the node key. On B_OK `out` holds the
			// parsed response (AuthURL for interactive login, or
			// MachineAuthorized). `insecure` disables TLS verification for
			// self-hosted control servers.
			status_t			Connect(const char* host, uint16 port,
									bool insecure, uint16 version,
									const uint8 machinePriv[32],
									const uint8 machinePub[32],
									const uint8 nodePub[32],
									const char* hostname, const char* authKey,
									RegisterResult& out);

			// Re-issue the register as a followup on `authURL`; the server
			// long-polls until the user finishes the browser login (or it times
			// out), so this blocks. Reuses the open HTTP/2 connection.
			status_t			PollAuthorized(const char* host, uint16 version,
									const uint8 nodePub[32], const char* hostname,
									const char* authURL, RegisterResult& out);

			// The tailcfg.EarlyNoise JSON captured during bootstrap (carries the
			// nodeKeyChallenge).
			const BString&		EarlyJson() const { return fEarlyJson; }

			Http2Conn&			Http2() { return fHttp2; }
			const char*			LastError() const { return fLastError.String(); }

private:
			ControlClient		fClient;
			ControlConn			fConn;
			Http2Conn			fHttp2;
			BString				fEarlyJson;
			BString				fLastError;
			bool				fReady;		// HTTP/2 up
};

}	// namespace ts


#endif	// TS_CONTROL_SESSION_H
