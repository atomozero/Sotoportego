/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TailscaleBackend.h"

#include <stdio.h>

#include "VPNProfile.h"


TailscaleBackend::TailscaleBackend()
	:
	VPNBackend("tailscale_backend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fLocalIP(""),
	fRemoteIP("")
{
}


TailscaleBackend::~TailscaleBackend()
{
}


status_t
TailscaleBackend::Connect(const VPNProfile& profile)
{
	// Phase 1: establish this node's persistent identity before anything else.
	// The machine/node/disco keypairs are loaded from the keystore, or minted
	// and stored on first use, keyed by the profile name so each tailnet
	// profile is a distinct device.
	if (profile.fName.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "Tailscale profile has no name");
		return B_BAD_VALUE;
	}

	bool createdAny = false;
	status_t result = fIdentity.LoadOrCreate(profile.fName.String(),
		&createdAny);
	if (result != B_OK) {
		_SetState(VPN_STATE_ERROR, "could not establish node identity");
		return result;
	}

	// Log the public node key (safe to log; the private half never leaves the
	// keystore) so identity persistence is observable across launches.
	BString nodePub = ts::TSIdentity::ToHex(fIdentity.NodePublic(), 32);
	printf("[tailscale] identity ready for '%s' (%s) node:%s\n",
		profile.fName.String(),
		createdAny ? "generated" : "reused",
		nodePub.String());

	// The control plane / magicsock / DERP stack isn't built yet: report a
	// clean, specific error rather than pretending to connect. Later phases
	// replace this with the ts2021 handshake.
	_SetState(VPN_STATE_ERROR,
		"control channel not implemented yet (identity ready)");
	return B_NOT_SUPPORTED;
}


status_t
TailscaleBackend::Disconnect()
{
	_SetState(VPN_STATE_DISCONNECTED);
	return B_OK;
}


VPNState
TailscaleBackend::State() const
{
	return fState;
}


VPNStats
TailscaleBackend::Stats() const
{
	return fStats;
}


const char*
TailscaleBackend::BackendName() const
{
	return "Tailscale";
}


BString
TailscaleBackend::LocalIP() const
{
	return fLocalIP;
}


BString
TailscaleBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
TailscaleBackend::RecoverIfCrashed()
{
	// Nothing to roll back yet: no tun slot, routes or resolv.conf are touched
	// until the data-plane phases land. Once they do, this mirrors
	// WireGuardBackend::RecoverIfCrashed() (tun/route/DNS teardown from a
	// recorded session file).
}


void
TailscaleBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	NotifyStateChanged(state, detail);
}
