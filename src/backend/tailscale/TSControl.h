/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONTROL_H
#define TS_CONTROL_H


#include <stddef.h>
#include <sys/types.h>

#include <String.h>
#include <SupportDefs.h>


// ts2021 control-protocol framing (Tailscale's control/controlbase wire format)
// and the small pieces around the Noise handshake that are specific to the
// control channel. The Noise cryptography itself lives in TSNoise; this module
// is the framing + parsing that wraps it.
//
// Wire format (verified against tailscale/control/controlbase):
//   * Initiation message (client -> control): a 5-byte header followed by the
//     96-byte Noise message 1.
//         [0..1] protocol version, big-endian uint16
//         [2]    message type = 1 (initiation)
//         [3..4] payload length, big-endian uint16 (= 96)
//         [5..]  Noise msg1: e(32) || enc_machine_static(48) || tag(16)
//   * Response/record messages (control -> client): a 3-byte header
//         [0]    message type (2 = response, 3 = error, 4 = record)
//         [1..2] payload length, big-endian uint16
//         [3..]  payload; for the handshake response, the 48-byte Noise msg2:
//                e(32) || tag(16)
//
// The Noise handshake also mixes a version-dependent prologue --
// "Tailscale Control Protocol v<version>" -- into the transcript hash on both
// sides, so the version we advertise in the initiation header must equal the
// version string we feed NoiseIK::InitInitiator as its prologue.
namespace ts {

// Default protocol version = tailcfg.CurrentCapabilityVersion at the time of
// writing. The control server echoes whatever version the client advertises
// into its own prologue, so any version the server still supports interoperates;
// this default is validated live against the coordination server / Headscale.
static const uint16 kControlProtocolVersion = 144;

// Message type bytes.
enum ControlMsgType {
	CONTROL_MSG_INITIATION	= 1,
	CONTROL_MSG_RESPONSE	= 2,
	CONTROL_MSG_ERROR		= 3,
	CONTROL_MSG_RECORD		= 4
};

// Header / payload sizes.
static const size_t kInitiationHeaderLen	= 5;
static const size_t kRecordHeaderLen		= 3;
static const size_t kInitiationPayloadLen	= 96;	// Noise msg1, empty payload
static const size_t kResponsePayloadLen		= 48;	// Noise msg2, empty payload
static const size_t kInitiationMsgLen		= kInitiationHeaderLen
												+ kInitiationPayloadLen;	// 101


// Build the Noise prologue string for a protocol version:
// "Tailscale Control Protocol v<version>".
BString		ControlPrologue(uint16 version);

// Frame a Noise initiation (msg1, exactly kInitiationPayloadLen bytes) into a
// ts2021 initiation message. Returns bytes written (kInitiationMsgLen) or -1 on
// bad length / insufficient capacity.
ssize_t		EncodeInitiation(const uint8* noiseMsg1, size_t noiseMsg1Len,
				uint16 version, uint8* out, size_t outCap);

// Parse a 3-byte record header. On success sets *outType and *outPayloadLen and
// returns kRecordHeaderLen; returns -1 if inLen is too small.
ssize_t		DecodeRecordHeader(const uint8* in, size_t inLen, uint8* outType,
				uint16* outPayloadLen);

// Extract the control server's Noise static public key from the JSON returned
// by GET <control>/key. Prefers the modern "publicKey":"mkey:<64 hex>" field.
// Writes 32 bytes to out. Returns true on success.
bool		ParseControlKey(const char* json, uint8 out[32]);

}	// namespace ts


#endif	// TS_CONTROL_H
