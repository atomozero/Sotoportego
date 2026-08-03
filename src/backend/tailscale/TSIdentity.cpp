/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSIdentity.h"

#include <string.h>

#include <File.h>
#include <Key.h>
#include <KeyStore.h>
#include <Message.h>
#include <Path.h>

#include "TSConfig.h"
#include "WireGuardCrypto.h"


namespace ts {

// Field names for the cached public-key file (<identity-dir>/identity).
static const char* const kIdentityLeaf		= "identity";
static const char* const kFieldMachinePub	= "machine_pub";
static const char* const kFieldNodePub		= "node_pub";
static const char* const kFieldDiscoPub		= "disco_pub";


// One hex digit -> its 0..15 value, or -1 if not a hex character.
static int
_HexNibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


TSIdentity::TSIdentity()
	:
	fProfileName(""),
	fValid(false)
{
	memset(&fMachine, 0, sizeof(fMachine));
	memset(&fNode, 0, sizeof(fNode));
	memset(&fDisco, 0, sizeof(fDisco));
}


status_t
TSIdentity::LoadOrCreate(const char* profileName, bool* outCreatedAny)
{
	if (profileName == NULL || *profileName == '\0')
		return B_BAD_VALUE;

	fValid = false;
	fProfileName = profileName;

	bool created = false;
	bool any = false;

	status_t result = _LoadOrCreateRole(KEY_MACHINE, fMachine, created);
	if (result != B_OK)
		return result;
	any = any || created;

	result = _LoadOrCreateRole(KEY_NODE, fNode, created);
	if (result != B_OK)
		return result;
	any = any || created;

	result = _LoadOrCreateRole(KEY_DISCO, fDisco, created);
	if (result != B_OK)
		return result;
	any = any || created;

	// Refresh the on-disk public cache whenever anything was (re)generated, or
	// simply if the file isn't there yet. Its failure is non-fatal: the keys
	// live in the keystore, this file is only an inspection aid.
	if (any)
		_WritePublicFile();

	fValid = true;
	if (outCreatedAny != NULL)
		*outCreatedAny = any;
	return B_OK;
}


status_t
TSIdentity::_LoadOrCreateRole(KeyRole role, Key25519& out, bool& outCreated)
{
	outCreated = false;

	BString id = _KeystoreId(fProfileName.String(), role);

	BKeyStore keystore;
	BPasswordKey key;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, id.String(), key) == B_OK) {
		// Existing identity: decode the stored private key and re-derive the
		// public half. A malformed stored value (wrong length / non-hex) is a
		// corrupted keystore entry -- surface it rather than silently minting a
		// new identity the peers won't recognise.
		const char* hex = key.Password();
		if (!FromHex(hex, out.priv, 32))
			return B_BAD_DATA;
		if (!wg::DhPublic(out.priv, out.pub))
			return B_ERROR;
		return B_OK;
	}

	// No key yet: generate a fresh keypair and persist the private half.
	if (!wg::DhGenerate(out.priv, out.pub))
		return B_ERROR;

	BString hexPriv = ToHex(out.priv, 32);
	BPasswordKey newKey(hexPriv.String(), B_KEY_PURPOSE_GENERIC, id.String());
	status_t result = keystore.AddKey(newKey);
	if (result != B_OK) {
		// Don't leave a keypair in memory that isn't backed by the keystore --
		// the next launch would generate a different one and the node would
		// look like a new device every time.
		memset(&out, 0, sizeof(out));
		return result;
	}

	outCreated = true;
	return B_OK;
}


status_t
TSIdentity::_WritePublicFile() const
{
	BPath dir;
	status_t result = TSConfig::IdentityDir(fProfileName.String(), &dir, true);
	if (result != B_OK)
		return result;
	result = dir.Append(kIdentityLeaf);
	if (result != B_OK)
		return result;

	BMessage stored;
	stored.AddString(kFieldMachinePub, ToHex(fMachine.pub, 32));
	stored.AddString(kFieldNodePub, ToHex(fNode.pub, 32));
	stored.AddString(kFieldDiscoPub, ToHex(fDisco.pub, 32));

	BFile file(dir.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (file.InitCheck() != B_OK)
		return file.InitCheck();
	return stored.Flatten(&file);
}


BString
TSIdentity::_KeystoreId(const char* profileName, KeyRole role)
{
	// Keystore identifiers are free-form strings (no filesystem constraints),
	// so a dotted namespace keyed by profile + role keeps every node's three
	// keys distinct and greppable in the keystore browser.
	BString id("sotoportego.tailscale.");
	id << profileName << "." << _RoleName(role);
	return id;
}


const char*
TSIdentity::_RoleName(KeyRole role)
{
	switch (role) {
		case KEY_MACHINE:	return "machine";
		case KEY_NODE:		return "node";
		case KEY_DISCO:		return "disco";
		default:			return "unknown";
	}
}


BString
TSIdentity::ToHex(const uint8* bytes, size_t len)
{
	static const char* const kHex = "0123456789abcdef";
	BString out;
	char* p = out.LockBuffer(len * 2 + 1);
	for (size_t i = 0; i < len; i++) {
		p[2 * i] = kHex[(bytes[i] >> 4) & 0x0f];
		p[2 * i + 1] = kHex[bytes[i] & 0x0f];
	}
	p[len * 2] = '\0';
	out.UnlockBuffer(len * 2);
	return out;
}


bool
TSIdentity::FromHex(const char* hex, uint8* out, size_t outLen)
{
	if (hex == NULL)
		return false;
	if (strlen(hex) != outLen * 2)
		return false;

	for (size_t i = 0; i < outLen; i++) {
		int hi = _HexNibble(hex[2 * i]);
		int lo = _HexNibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return false;
		out[i] = (uint8)((hi << 4) | lo);
	}
	return true;
}

}	// namespace ts
