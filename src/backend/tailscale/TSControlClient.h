/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONTROL_CLIENT_H
#define TS_CONTROL_CLIENT_H


#include <String.h>
#include <SupportDefs.h>

#include "TSNoise.h"
#include "TSTls.h"


// Establishes the ts2021 control channel: fetches the control server's Noise
// static key, runs the Noise IK handshake over an HTTP-Upgraded TLS connection
// to `<control>/ts2021`, and leaves the encrypted stream open for the control
// messages (RegisterRequest / MapRequest) that follow in later phases.
//
// The HTTP Upgrade dance matches Tailscale's control/controlhttp exactly:
//   POST /ts2021 HTTP/1.1
//   Upgrade: tailscale-control-protocol
//   Connection: upgrade
//   X-Tailscale-Handshake: <base64-std of the framed Noise initiation>
// The server replies 101 Switching Protocols and then writes the framed Noise
// response (a 51-byte record) directly on the now-raw connection; from there
// the transport keys from Split() encrypt the record stream.
namespace ts {

class ControlClient {
public:
								ControlClient();
								~ControlClient();

			// Run the full handshake against `host:port` using our machine
			// static keypair. Fetches `/key`, opens the upgraded connection,
			// completes the Noise handshake, and on success fills `outKeys`
			// (initiator view: sendKey = us->control) and keeps the TLS stream
			// open in Stream() for the record phase. `insecure` disables TLS
			// certificate verification (self-hosted Headscale with an out-of-band
			// trusted key). Returns B_OK, or an error with LastError() set.
			status_t			Handshake(const char* host, uint16 port,
									bool insecure,
									const uint8 machinePriv[32],
									const uint8 machinePub[32],
									uint16 version,
									NoiseTransportKeys* outKeys);

			// The control server's Noise static public key, populated after a
			// successful (or attempted) Handshake.
			const uint8*		ControlKey() const { return fControlKey; }

			TlsClient&			Stream() { return fTls; }
			const char*			LastError() const { return fLastError.String(); }

private:
			status_t			_FetchControlKey(const char* host, uint16 port,
									bool insecure);
			status_t			_ReadUpgradeResponse(uint8* body,
									size_t bodyCap, size_t* outBodyLen);

			TlsClient			fTls;
			uint8				fControlKey[32];
			BString				fLastError;
};

}	// namespace ts


#endif	// TS_CONTROL_CLIENT_H
