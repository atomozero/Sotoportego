/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_PROFILE_H
#define VPN_PROFILE_H


#include <String.h>
#include <SupportDefs.h>

class BMessage;


// Identifies which pluggable backend a profile is meant for. OpenVPN and
// WireGuard are implemented; Tailscale is being built from scratch in-process
// (see design/tailscale/), IPSec is still a placeholder for the seam. The
// values are part of the on-the-wire IPC protocol (carried as an int32 in
// BMessages) and are persisted in the profile store, so DO NOT renumber them;
// only append new backends at the end.
enum VPNBackendType {
	VPN_BACKEND_OPENVPN		= 0,
	VPN_BACKEND_WIREGUARD	= 1,
	VPN_BACKEND_IPSEC		= 2,
	VPN_BACKEND_TAILSCALE	= 3
};


// A user-defined connection profile. This is intentionally minimal for
// Milestone 1; real .ovpn parsing and credential storage land later. The
// profile is value-semantic and round-trips through a BMessage for IPC.
class VPNProfile {
public:
								VPNProfile();
								~VPNProfile();

			status_t			Archive(BMessage* into) const;
			status_t			Unarchive(const BMessage& from);

			VPNBackendType		fBackendType;
			BString				fName;
			BString				fServer;
			uint16				fPort;
			BString				fUsername;
	// Transport protocol the backend should use ("udp" or "tcp"); extracted
	// from the .ovpn `proto` directive when imported. Defaults to "udp" since
	// that is OpenVPN's default when the directive is absent.
			BString				fProtocol;
	// Path to the underlying backend config (e.g. an .ovpn file). Stored as
	// a reference; the file itself stays where the user picked it from.
			BString				fConfigPath;
	// Optional Tailscale pre-auth key. When non-empty the node registers
	// non-interactively (Auth.AuthKey in the RegisterRequest) instead of
	// handing off to the browser for SSO login. Empty for every other backend.
			BString				fAuthKey;
};


#endif	// VPN_PROFILE_H
