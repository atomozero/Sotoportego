/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_PROFILE_H
#define VPN_PROFILE_H


#include <String.h>
#include <SupportDefs.h>

class BMessage;


// Identifies which pluggable backend a profile is meant for. Only OpenVPN is
// implemented this milestone; the others are placeholders for the seam.
enum VPNBackendType {
	VPN_BACKEND_OPENVPN		= 0,
	VPN_BACKEND_WIREGUARD	= 1,
	VPN_BACKEND_IPSEC		= 2
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
	// Path to the underlying backend config (e.g. an .ovpn file). Parsing is
	// out of scope this milestone.
			BString				fConfigPath;
};


#endif	// VPN_PROFILE_H
