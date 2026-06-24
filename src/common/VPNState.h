/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_STATE_H
#define VPN_STATE_H


// High-level lifecycle state of a VPN connection, as owned by the daemon and
// reported to clients. The integer values are part of the on-the-wire IPC
// protocol (carried as an int32 in BMessages), so DO NOT renumber them; only
// append new states at the end.
enum VPNState {
	VPN_STATE_DISCONNECTED	= 0,
	VPN_STATE_CONNECTING	= 1,
	VPN_STATE_AUTHENTICATING = 2,
	VPN_STATE_CONNECTED		= 3,
	VPN_STATE_RECONNECTING	= 4,
	VPN_STATE_ERROR			= 5
};


// Returns a stable, human-readable name for a state ("Connected", ...).
// Never returns NULL; unknown values map to "Unknown".
const char* vpn_state_name(VPNState state);


#endif	// VPN_STATE_H
