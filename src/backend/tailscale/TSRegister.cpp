/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSRegister.h"

#include <string.h>

#include "TSIdentity.h"		// ToHex


namespace ts {

// --- tiny JSON field readers ----------------------------------------------
//
// The RegisterResponse fields we need (AuthURL, MachineAuthorized,
// NodeKeyExpired, Error) are top-level scalars, so a targeted `"key":` scan is
// enough; we deliberately don't pull in a full JSON parser. Values are read as
// they appear on the wire (Go's encoding/json does not escape the characters
// that occur in these fields -- URLs use %xx, not \uXXXX).

static bool
json_string(const BString& doc, const char* key, BString& out)
{
	BString needle;
	needle << "\"" << key << "\"";
	int k = doc.FindFirst(needle.String());
	if (k < 0)
		return false;
	k += needle.Length();
	// skip spaces and the colon
	while (k < doc.Length() && (doc[k] == ' ' || doc[k] == ':'))
		k++;
	if (k >= doc.Length() || doc[k] != '"')
		return false;
	k++;	// opening quote
	BString value;
	while (k < doc.Length() && doc[k] != '"') {
		if (doc[k] == '\\' && k + 1 < doc.Length()) {
			// Minimal unescape: keep the escaped char verbatim (covers \/ and
			// \\ which are all that appear in these URL/string fields).
			k++;
			value << doc[k];
		} else {
			value << doc[k];
		}
		k++;
	}
	out = value;
	return true;
}


static bool
json_bool(const BString& doc, const char* key)
{
	BString needle;
	needle << "\"" << key << "\"";
	int k = doc.FindFirst(needle.String());
	if (k < 0)
		return false;
	k += needle.Length();
	while (k < doc.Length() && (doc[k] == ' ' || doc[k] == ':'))
		k++;
	return doc.FindFirst("true", k) == k;
}


status_t
Register(Http2Conn& h2, const char* host, uint16 version,
	const uint8 nodePub[32], const char* hostname, const char* authKey,
	const char* followup, RegisterResult& out)
{
	out.httpStatus = 0;
	out.machineAuthorized = false;
	out.nodeKeyExpired = false;
	out.authURL = "";
	out.error = "";

	// Build the RegisterRequest JSON. Omitted fields (OldNodeKey, Expiry,
	// Followup, Timestamp, ...) default to zero server-side. The node key is
	// serialised in Tailscale's "nodekey:<hex>" text form.
	BString nodeHex = TSIdentity::ToHex(nodePub, 32);

	BString body;
	body << "{";
	body << "\"Version\":" << (int32)version << ",";
	body << "\"NodeKey\":\"nodekey:" << nodeHex << "\",";
	if (authKey != NULL && *authKey != '\0')
		body << "\"Auth\":{\"AuthKey\":\"" << authKey << "\"},";
	if (followup != NULL && *followup != '\0')
		body << "\"Followup\":\"" << followup << "\",";
	body << "\"Hostinfo\":{";
	body << "\"IPNVersion\":\"0.1.0\",";
	body << "\"Hostname\":\"" << (hostname != NULL ? hostname : "haiku") << "\",";
	body << "\"OS\":\"haiku\"";
	body << "}";
	body << "}";

	int status = 0;
	BString resp;
	status_t result = h2.Request("POST", "https", host, "/machine/register",
		"application/json", (const uint8*)body.String(), body.Length(),
		&status, &resp);
	if (result != B_OK)
		return result;

	out.httpStatus = status;
	// Parse whatever JSON came back (a RegisterResponse, or an error document).
	json_string(resp, "AuthURL", out.authURL);
	json_string(resp, "Error", out.error);
	out.machineAuthorized = json_bool(resp, "MachineAuthorized");
	out.nodeKeyExpired = json_bool(resp, "NodeKeyExpired");
	return B_OK;
}

}	// namespace ts
