/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSControlSession.h"


namespace ts {

ControlSession::ControlSession()
	:
	fEarlyJson(""),
	fLastError(""),
	fReady(false)
{
}


status_t
ControlSession::Connect(const char* host, uint16 port, bool insecure,
	uint16 version, const uint8 machinePriv[32], const uint8 machinePub[32],
	const uint8 nodePub[32], const char* hostname, const char* authKey,
	RegisterResult& out)
{
	// 1) Noise handshake to the control server.
	NoiseTransportKeys keys;
	status_t result = fClient.Handshake(host, port, insecure, machinePriv,
		machinePub, version, &keys);
	if (result != B_OK) {
		fLastError.SetToFormat("control handshake failed: %s",
			fClient.LastError());
		return result;
	}

	// 2) Encrypted record stream (seed the pushback the handshake buffered).
	fConn.Init(&fClient.Stream(), keys, fClient.Pending(), fClient.PendingLen());

	// 3) HTTP/2 bootstrap (consumes the early payload, does the SETTINGS dance).
	fHttp2.Init(&fConn);
	result = fHttp2.Bootstrap(&fEarlyJson);
	if (result != B_OK) {
		fLastError.SetToFormat("HTTP/2 bootstrap failed: %s",
			fHttp2.LastError());
		return result;
	}
	fReady = true;

	// 4) Initial registration.
	result = Register(fHttp2, host, version, nodePub, hostname, authKey, NULL,
		out);
	if (result != B_OK) {
		fLastError.SetToFormat("register failed: %s", fHttp2.LastError());
		return result;
	}
	return B_OK;
}


status_t
ControlSession::PollAuthorized(const char* host, uint16 version,
	const uint8 nodePub[32], const char* hostname, const char* authURL,
	RegisterResult& out)
{
	if (!fReady) {
		fLastError = "control session not connected";
		return B_NO_INIT;
	}
	status_t result = Register(fHttp2, host, version, nodePub, hostname, NULL,
		authURL, out);
	if (result != B_OK)
		fLastError.SetToFormat("followup register failed: %s",
			fHttp2.LastError());
	return result;
}

}	// namespace ts
