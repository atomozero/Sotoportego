/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TailscaleBackend.h"

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
TailscaleBackend::Connect(const VPNProfile& /*profile*/)
{
	// Phase 0 scaffold: the backend is wired into the daemon and can be
	// selected, but the control plane / magicsock / DERP stack isn't built
	// yet. Report a clean error rather than pretending to connect, so the
	// seam is exercisable end to end while the real phases land.
	_SetState(VPN_STATE_ERROR, "Tailscale backend not implemented yet");
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
