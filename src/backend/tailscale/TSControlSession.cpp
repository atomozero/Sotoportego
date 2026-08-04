/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSControlSession.h"

#include <string.h>

#include "TSControlClient.h"
#include "TSControlConn.h"


namespace ts {

ControlSession::ControlSession()
	:
	fHost(""),
	fPort(443),
	fInsecure(false),
	fVersion(0),
	fHaveParams(false),
	fClient(NULL),
	fConn(NULL),
	fEarlyJson(""),
	fLastError("")
{
	memset(fMachinePriv, 0, sizeof(fMachinePriv));
	memset(fMachinePub, 0, sizeof(fMachinePub));
}


ControlSession::~ControlSession()
{
	// Order matters: Http2Conn refs fConn refs fClient's TLS stream.
	delete fConn;
	delete fClient;
}


status_t
ControlSession::_Establish()
{
	if (!fHaveParams) {
		fLastError = "control session not configured";
		return B_NO_INIT;
	}

	// Drop any prior connection (the server closed it after the last response).
	// The Http2Conn is re-Init'd below; tear down the record stream + TLS.
	delete fConn;
	fConn = NULL;
	delete fClient;
	fClient = NULL;

	fClient = new ControlClient();
	fConn = new ControlConn();

	// 1) Noise handshake to the control server.
	NoiseTransportKeys keys;
	status_t result = fClient->Handshake(fHost.String(), fPort, fInsecure,
		fMachinePriv, fMachinePub, fVersion, &keys);
	if (result != B_OK) {
		fLastError.SetToFormat("control handshake failed: %s",
			fClient->LastError());
		return result;
	}

	// 2) Encrypted record stream (seed the handshake's pushback bytes).
	fConn->Init(&fClient->Stream(), keys, fClient->Pending(),
		fClient->PendingLen());

	// 3) HTTP/2 bootstrap (consumes the early payload, does the SETTINGS dance).
	fHttp2.Init(fConn);
	result = fHttp2.Bootstrap(&fEarlyJson);
	if (result != B_OK) {
		fLastError.SetToFormat("HTTP/2 bootstrap failed: %s",
			fHttp2.LastError());
		return result;
	}
	return B_OK;
}


status_t
ControlSession::Connect(const char* host, uint16 port, bool insecure,
	uint16 version, const uint8 machinePriv[32], const uint8 machinePub[32],
	const uint8 nodePub[32], const char* hostname, const char* authKey,
	RegisterResult& out)
{
	// Capture the endpoint + machine key so later calls can re-handshake.
	fHost = host;
	fPort = port;
	fInsecure = insecure;
	fVersion = version;
	memcpy(fMachinePriv, machinePriv, 32);
	memcpy(fMachinePub, machinePub, 32);
	fHaveParams = true;

	status_t result = _Establish();
	if (result != B_OK)
		return result;

	result = Register(fHttp2, host, version, nodePub, hostname, authKey, NULL,
		out);
	if (result != B_OK)
		fLastError.SetToFormat("register failed: %s", fHttp2.LastError());
	return result;
}


status_t
ControlSession::PollAuthorized(const char* host, uint16 version,
	const uint8 nodePub[32], const char* hostname, const char* authURL,
	RegisterResult& out)
{
	// Each poll rides a fresh connection -- the server closed the previous one.
	status_t result = _Establish();
	if (result != B_OK)
		return result;

	result = Register(fHttp2, host, version, nodePub, hostname, NULL, authURL,
		out);
	if (result != B_OK)
		fLastError.SetToFormat("followup register failed: %s",
			fHttp2.LastError());
	return result;
}


status_t
ControlSession::Establish()
{
	return _Establish();
}

}	// namespace ts
