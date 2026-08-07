/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSControl.h"

#include <string.h>

#include "TSIdentity.h"	// ToHex/FromHex


namespace ts {

// The control server presents its Noise static as an "mkey:"-prefixed 64-char
// hex string, in a JSON document like:
//   { "publicKey": "mkey:7d27...73b", "legacyPublicKey": "mkey:9e51..." }
static const char* const kControlKeyPrefix	= "mkey:";
static const char* const kControlKeyField	= "\"publicKey\"";


BString
ControlPrologue(uint16 version)
{
	BString prologue;
	prologue.SetToFormat("Tailscale Control Protocol v%u", (unsigned)version);
	return prologue;
}


ssize_t
EncodeInitiation(const uint8* noiseMsg1, size_t noiseMsg1Len, uint16 version,
	uint8* out, size_t outCap)
{
	if (noiseMsg1 == NULL || noiseMsg1Len != kInitiationPayloadLen)
		return -1;
	if (out == NULL || outCap < kInitiationMsgLen)
		return -1;

	out[0] = (uint8)(version >> 8);
	out[1] = (uint8)(version & 0xff);
	out[2] = (uint8)CONTROL_MSG_INITIATION;
	out[3] = (uint8)(kInitiationPayloadLen >> 8);
	out[4] = (uint8)(kInitiationPayloadLen & 0xff);
	memcpy(out + kInitiationHeaderLen, noiseMsg1, kInitiationPayloadLen);

	return (ssize_t)kInitiationMsgLen;
}


ssize_t
DecodeRecordHeader(const uint8* in, size_t inLen, uint8* outType,
	uint16* outPayloadLen)
{
	if (in == NULL || inLen < kRecordHeaderLen)
		return -1;
	if (outType != NULL)
		*outType = in[0];
	if (outPayloadLen != NULL)
		*outPayloadLen = (uint16)(((uint16)in[1] << 8) | (uint16)in[2]);
	return (ssize_t)kRecordHeaderLen;
}


bool
ParseControlKey(const char* json, uint8 out[32])
{
	if (json == NULL)
		return false;

	BString doc(json);

	// Locate the modern "publicKey" field, then the first "mkey:" hex that
	// follows it. Falls back to any "mkey:" in the document if the field name
	// isn't present (defensive; the endpoint always labels it).
	int fieldPos = doc.FindFirst(kControlKeyField);
	int searchFrom = (fieldPos >= 0) ? fieldPos : 0;

	int keyPos = doc.FindFirst(kControlKeyPrefix, searchFrom);
	if (keyPos < 0)
		return false;
	keyPos += (int)strlen(kControlKeyPrefix);

	// The next 64 characters must be the hex key.
	if (doc.Length() - keyPos < 64)
		return false;
	BString hex;
	doc.CopyInto(hex, keyPos, 64);

	return TSIdentity::FromHex(hex.String(), out, 32);
}

}	// namespace ts
