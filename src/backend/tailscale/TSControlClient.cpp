/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSControlClient.h"

#include <stdio.h>
#include <string.h>

#include "TSControl.h"


namespace ts {

// The well-known Noise-upgrade path and header values (control/controlhttp).
static const char* const kUpgradePath		= "/ts2021";
static const char* const kUpgradeHeaderValue = "tailscale-control-protocol";
static const char* const kHandshakeHeader	= "X-Tailscale-Handshake";


// Standard base64 (RFC 4648) with padding, for the X-Tailscale-Handshake header.
static BString
base64_encode(const uint8* data, size_t len)
{
	static const char* const kAlphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	BString out;
	size_t i = 0;
	while (i + 3 <= len) {
		uint32 n = ((uint32)data[i] << 16) | ((uint32)data[i + 1] << 8)
			| (uint32)data[i + 2];
		out << kAlphabet[(n >> 18) & 0x3f] << kAlphabet[(n >> 12) & 0x3f]
			<< kAlphabet[(n >> 6) & 0x3f] << kAlphabet[n & 0x3f];
		i += 3;
	}
	size_t rem = len - i;
	if (rem == 1) {
		uint32 n = (uint32)data[i] << 16;
		out << kAlphabet[(n >> 18) & 0x3f] << kAlphabet[(n >> 12) & 0x3f]
			<< "==";
	} else if (rem == 2) {
		uint32 n = ((uint32)data[i] << 16) | ((uint32)data[i + 1] << 8);
		out << kAlphabet[(n >> 18) & 0x3f] << kAlphabet[(n >> 12) & 0x3f]
			<< kAlphabet[(n >> 6) & 0x3f] << "=";
	}
	return out;
}


ControlClient::ControlClient()
	:
	fLastError("")
{
	memset(fControlKey, 0, sizeof(fControlKey));
}


ControlClient::~ControlClient()
{
}


status_t
ControlClient::_FetchControlKey(const char* host, uint16 port, bool insecure)
{
	// GET /key on its own short-lived TLS connection; the version query just
	// asks the server to speak a compatible key format.
	BString path;
	path.SetToFormat("/key?v=%u", (unsigned)kControlProtocolVersion);

	int status = 0;
	BString body;
	status_t result = HttpsGet(host, port, path.String(), insecure, &status,
		&body);
	if (result != B_OK) {
		fLastError.SetToFormat("control /key fetch failed: %s",
			strerror(result));
		return result;
	}
	if (status != 200) {
		fLastError.SetToFormat("control /key returned HTTP %d", status);
		return B_ERROR;
	}
	if (!ParseControlKey(body.String(), fControlKey)) {
		fLastError = "could not parse control key from /key response";
		return B_ERROR;
	}
	return B_OK;
}


status_t
ControlClient::_ReadUpgradeResponse(uint8* body, size_t bodyCap,
	size_t* outBodyLen)
{
	// Accumulate the raw upgrade response: HTTP status line + headers, then --
	// once past the blank line -- the framed Noise response the server writes on
	// the upgraded connection.
	uint8 buf[8192];
	size_t total = 0;
	int headerEnd = -1;

	while (total < sizeof(buf)) {
		ssize_t n = fTls.Read(buf + total, sizeof(buf) - total);
		if (n <= 0)
			break;
		total += (size_t)n;

		if (headerEnd < 0) {
			// Scan for the CRLFCRLF that ends the HTTP headers.
			for (size_t i = 0; i + 3 < total; i++) {
				if (buf[i] == '\r' && buf[i + 1] == '\n'
						&& buf[i + 2] == '\r' && buf[i + 3] == '\n') {
					headerEnd = (int)(i + 4);
					break;
				}
			}
		}
		// Stop once we have the headers plus at least a full response record
		// (3-byte header + 48-byte Noise msg2).
		if (headerEnd >= 0
				&& total - (size_t)headerEnd >= kRecordHeaderLen
					+ kResponsePayloadLen) {
			break;
		}
	}

	if (headerEnd < 0) {
		fLastError = "no HTTP header terminator in upgrade response";
		return B_ERROR;
	}

	// The status line must be 101 Switching Protocols.
	if (memmem(buf, (size_t)headerEnd, " 101 ", 5) == NULL) {
		BString head((const char*)buf,
			headerEnd < 120 ? headerEnd : 120);
		fLastError.SetToFormat("upgrade not accepted: %s", head.String());
		return B_ERROR;
	}

	size_t have = total - (size_t)headerEnd;
	if (have > bodyCap)
		have = bodyCap;
	memcpy(body, buf + headerEnd, have);
	*outBodyLen = have;
	return B_OK;
}


status_t
ControlClient::Handshake(const char* host, uint16 port, bool insecure,
	const uint8 machinePriv[32], const uint8 machinePub[32], uint16 version,
	NoiseTransportKeys* outKeys)
{
	if (host == NULL || machinePriv == NULL || machinePub == NULL)
		return B_BAD_VALUE;

	// 1) Learn the control server's Noise static key.
	status_t result = _FetchControlKey(host, port, insecure);
	if (result != B_OK)
		return result;

	// 2) Build the Noise initiation (msg1, empty payload) with the version
	//    prologue, and frame it as a ts2021 initiation message.
	BString prologue = ControlPrologue(version);
	NoiseIK noise;
	noise.InitInitiator(machinePriv, machinePub, fControlKey,
		prologue.String(), prologue.Length());

	uint8 msg1[128];
	ssize_t m1 = noise.WriteMessage1(NULL, 0, msg1, sizeof(msg1));
	if (m1 < 0 || (size_t)m1 != kInitiationPayloadLen) {
		fLastError = "failed to build Noise initiation";
		return B_ERROR;
	}

	uint8 initFrame[kInitiationMsgLen];
	ssize_t framed = EncodeInitiation(msg1, (size_t)m1, version, initFrame,
		sizeof(initFrame));
	if (framed < 0) {
		fLastError = "failed to frame initiation";
		return B_ERROR;
	}
	BString initB64 = base64_encode(initFrame, (size_t)framed);

	// 3) Open the upgraded connection and POST the handshake header.
	result = fTls.Connect(host, port);
	if (result != B_OK) {
		fLastError.SetToFormat("TLS connect for /ts2021 failed: %s",
			fTls.LastError());
		return result;
	}

	BString req;
	req.SetToFormat(
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: %s\r\n"
		"Connection: upgrade\r\n"
		"%s: %s\r\n"
		"User-Agent: Sotoportego/0.1\r\n"
		"Content-Length: 0\r\n\r\n",
		kUpgradePath, host, kUpgradeHeaderValue,
		kHandshakeHeader, initB64.String());
	if (fTls.Write(req.String(), req.Length()) < 0) {
		fLastError = "failed to send upgrade request";
		return B_IO_ERROR;
	}

	// 4) Read the 101 response and the framed Noise reply.
	uint8 body[256];
	size_t bodyLen = 0;
	result = _ReadUpgradeResponse(body, sizeof(body), &bodyLen);
	if (result != B_OK)
		return result;

	uint8 type = 0;
	uint16 payloadLen = 0;
	if (DecodeRecordHeader(body, bodyLen, &type, &payloadLen)
			!= (ssize_t)kRecordHeaderLen) {
		fLastError = "short control response record";
		return B_ERROR;
	}
	if (type == CONTROL_MSG_ERROR) {
		fLastError = "control server returned a handshake error record";
		return B_ERROR;
	}
	if (type != CONTROL_MSG_RESPONSE) {
		fLastError.SetToFormat("unexpected control record type %u", type);
		return B_ERROR;
	}
	if (bodyLen < kRecordHeaderLen + payloadLen) {
		fLastError = "truncated control response payload";
		return B_ERROR;
	}

	// 5) Consume the Noise response; a verifying decrypt proves the whole
	//    handshake (version prologue, framing, keys) matched the server.
	uint8 hsPayload[64];
	ssize_t got = noise.ReadMessage2(body + kRecordHeaderLen, payloadLen,
		hsPayload, sizeof(hsPayload));
	if (got < 0) {
		fLastError = "Noise response failed to verify (version/protocol "
			"mismatch)";
		return B_ERROR;
	}

	if (outKeys != NULL)
		noise.Split(*outKeys);
	return B_OK;
}

}	// namespace ts
