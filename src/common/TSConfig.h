/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONFIG_H
#define TS_CONFIG_H


#include <String.h>
#include <SupportDefs.h>

class BPath;


// Tailscale per-profile configuration and on-disk identity layout.
//
// A tailnet "profile" is not a file import the way an .ovpn/.conf is; it is a
// persistent identity (machine key + node key + disco key + the last auth
// state) that must survive daemon restarts so the node isn't re-registered on
// every launch. TSConfig owns the two things that identity needs:
//
//   * the *non-secret* settings -- which control server to talk to -- persisted
//     as a small flattened BMessage under the profile's identity directory, and
//   * the directory layout itself, rooted at
//     ~/config/settings/Sotoportego/tailscale/<profile>/, where Phase 1 stores
//     the keypairs (private halves go to the Haiku keystore, never a flat file).
//
// The optional pre-auth key is deliberately *not* persisted by Save(): it is a
// secret used for non-interactive join and, if it is ever to be remembered,
// belongs in the keystore alongside the private keys, not in the plaintext
// config. It is carried here only for the lifetime of a single Connect.
namespace ts {

// Default coordination server when a profile doesn't name its own (a Headscale
// deployment supplies its own base URL, e.g. "https://headscale.example.net").
extern const char* const kDefaultControlURL;


class TSConfig {
public:
								TSConfig();

			// Reset to defaults: control URL = kDefaultControlURL, no auth key,
			// no profile.
			void				MakeDefault();

			// Load the non-secret config for `profileName` from
			// <IdentityDir>/config. A missing file is not an error -- it yields
			// the defaults (this is a fresh identity). The pre-auth key is left
			// untouched (it is never persisted). On success fProfileName is set
			// so a later Save() targets the same directory.
			status_t			Load(const char* profileName);

			// Persist the non-secret config (control URL) for fProfileName,
			// creating the identity directory if needed. Atomic replace, like
			// ProfileStore. Requires fProfileName to be set.
			status_t			Save() const;

			// The control server base URL, no trailing slash
			// (e.g. "https://controlplane.tailscale.com").
			const BString&		ControlURL() const { return fControlURL; }
			void				SetControlURL(const char* url);

			// Optional, transient pre-auth key for non-interactive join. Empty
			// means "use the interactive browser login flow".
			const BString&		AuthKey() const { return fAuthKey; }
			void				SetAuthKey(const char* key) { fAuthKey = key; }

			const BString&		ProfileName() const { return fProfileName; }

	// --- Path helpers ---------------------------------------------------------

	// ~/config/settings/Sotoportego/tailscale, created (mkdir -p) when
	// createDir is true.
	static	status_t			BaseDir(BPath* out, bool createDir);

	// ~/config/settings/Sotoportego/tailscale/<profile>, created when
	// createDir is true. The profile name is sanitised to a single safe path
	// component (see _SanitizeComponent), so an arbitrary user-chosen name can
	// never escape the base directory or introduce nested folders.
	static	status_t			IdentityDir(const char* profileName,
									BPath* out, bool createDir);

private:
	static	BString				_SanitizeComponent(const char* name);
	static	status_t			_ConfigFilePath(const char* profileName,
									BPath* out, bool createDir);

			BString				fControlURL;
			BString				fAuthKey;
			BString				fProfileName;
};

}	// namespace ts


#endif	// TS_CONFIG_H
