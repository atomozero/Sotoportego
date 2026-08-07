/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_IDENTITY_H
#define TS_IDENTITY_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>


// A tailnet node's persistent cryptographic identity.
//
// Tailscale keys a device with three long-lived Curve25519 keypairs, each with
// a distinct job (design/tailscale/DESIGN.md §4.1):
//
//   * machine key -- secures the ts2021 Noise channel to the control server and
//     identifies the device to it;
//   * node key    -- the WireGuard key advertised to peers (rotatable);
//   * disco key   -- used only by the disco endpoint-probing protocol, kept
//     separate so endpoint discovery can't be correlated to the node key.
//
// All three must survive daemon restarts, or the node re-registers on every
// launch. TSIdentity is the single owner of that persistence:
//
//   * Private halves go into the Haiku keystore (BKeyStore), hex-encoded so the
//     32 raw bytes (which contain NULs) survive the string-oriented API, never
//     to a plaintext file.
//   * Public halves are derived from the private keys via OpenSSL X25519 (the
//     same wg::DhPublic the WireGuard backend uses) on every load, and also
//     cached to <identity-dir>/identity purely for inspection/logging.
//
// LoadOrCreate is idempotent: the first call for a fresh profile generates and
// persists all three keypairs; every later call (including after a restart)
// reloads the very same keys.
namespace ts {

enum KeyRole {
	KEY_MACHINE	= 0,
	KEY_NODE	= 1,
	KEY_DISCO	= 2
};


// A raw Curve25519 keypair. Both halves are exactly 32 bytes.
struct Key25519 {
	uint8	priv[32];
	uint8	pub[32];
};


class TSIdentity {
public:
								TSIdentity();

			// Load the identity for `profileName`, generating and persisting
			// any of the three keypairs that don't exist yet. Idempotent.
			// Returns B_OK with all keys populated, or an error (keystore
			// failure, bad profile name, crypto failure) with the object left
			// unusable. `outCreatedAny`, when non-NULL, is set true if at least
			// one key had to be freshly generated (i.e. first run for this
			// profile).
			status_t			LoadOrCreate(const char* profileName,
									bool* outCreatedAny = NULL);

			bool				IsValid() const { return fValid; }
			const BString&		ProfileName() const { return fProfileName; }

			// Public keys (32 bytes), valid after a successful LoadOrCreate.
			const uint8*		MachinePublic() const { return fMachine.pub; }
			const uint8*		NodePublic() const { return fNode.pub; }
			const uint8*		DiscoPublic() const { return fDisco.pub; }

			// Private keys (32 bytes), valid after a successful LoadOrCreate.
			// Needed by the Noise handshake (machine) and the WG data plane
			// (node); handle with care and never log.
			const uint8*		MachinePrivate() const { return fMachine.priv; }
			const uint8*		NodePrivate() const { return fNode.priv; }
			const uint8*		DiscoPrivate() const { return fDisco.priv; }

	// --- hex helpers (also used by later wire formatting / logging) -----------

	// Lowercase hex of `len` bytes.
	static	BString				ToHex(const uint8* bytes, size_t len);
	// Decode exactly `outLen` bytes worth of hex (2*outLen chars) into `out`.
	// Returns false on wrong length or a non-hex character.
	static	bool				FromHex(const char* hex, uint8* out,
									size_t outLen);

private:
			status_t			_LoadOrCreateRole(KeyRole role, Key25519& out,
									bool& outCreated);
			status_t			_WritePublicFile() const;

	static	BString				_KeystoreId(const char* profileName,
									KeyRole role);
	static	const char*			_RoleName(KeyRole role);

			Key25519			fMachine;
			Key25519			fNode;
			Key25519			fDisco;
			BString				fProfileName;
			bool				fValid;
};

}	// namespace ts


#endif	// TS_IDENTITY_H
