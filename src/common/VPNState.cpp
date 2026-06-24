/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VPNState.h"


const char*
vpn_state_name(VPNState state)
{
	switch (state) {
		case VPN_STATE_DISCONNECTED:
			return "Disconnected";
		case VPN_STATE_CONNECTING:
			return "Connecting";
		case VPN_STATE_AUTHENTICATING:
			return "Authenticating";
		case VPN_STATE_CONNECTED:
			return "Connected";
		case VPN_STATE_RECONNECTING:
			return "Reconnecting";
		case VPN_STATE_ERROR:
			return "Error";
	}

	return "Unknown";
}
