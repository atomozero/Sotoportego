/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WireGuardBackend.h"

#include <stdio.h>
#include <unistd.h>

#include <MessageRunner.h>

#include "VPNProfile.h"


WireGuardBackend::WireGuardBackend()
	:
	VPNBackend("WireGuardBackend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fConfig(),
	fLocalIP(),
	fRemoteIP(),
	fTunInterface(),
	fTunNode(),
	fUdpSocket(-1),
	fReader(-1),
	fTimer(NULL),
	fStopRequested(false)
{
}


WireGuardBackend::~WireGuardBackend()
{
	_Cleanup();
}


status_t
WireGuardBackend::Connect(const VPNProfile& profile)
{
	if (fState != VPN_STATE_DISCONNECTED && fState != VPN_STATE_ERROR)
		return B_NOT_ALLOWED;

	if (Looper() == NULL) {
		// The backend must be attached to the daemon's looper before use, so
		// BMessenger(this) (for timer ticks) is addressable.
		return B_NO_INIT;
	}

	if (profile.fConfigPath.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "profile has no WireGuard config path");
		return B_BAD_VALUE;
	}

	// Load and validate the .conf up front so a broken profile fails cleanly.
	fConfig = WireGuardConfig();
	if (!WireGuardConfigParser::ParseFile(profile.fConfigPath.String(),
			fConfig)) {
		_SetState(VPN_STATE_ERROR, "cannot read WireGuard config");
		return B_ERROR;
	}
	if (!fConfig.IsComplete()) {
		_SetState(VPN_STATE_ERROR,
			"WireGuard config is missing a key or endpoint");
		return B_BAD_VALUE;
	}

	fRemoteIP = fConfig.peer.endpointHost;
	fLocalIP = fConfig.address;		// display value; refined once tun is up
	fStopRequested = false;
	fStats.Reset();

	// TODO(wireguard): the real bring-up sequence goes here, e.g.
	//   _SetState(VPN_STATE_CONNECTING);
	//   if (!_BringUpTun())        { _SetState(VPN_STATE_ERROR, ...); return B_ERROR; }
	//   if (!_OpenUdpSocket())     { _Cleanup(); _SetState(VPN_STATE_ERROR, ...); return B_ERROR; }
	//   if (!_PerformHandshake())  { _Cleanup(); _SetState(VPN_STATE_ERROR, ...); return B_ERROR; }
	//   _StartReader();            // + arm rekey / keepalive timers via fTimer
	//   return B_OK;               // CONNECTED is posted from the reader once transport keys are live
	//
	// The data plane (Noise IK handshake + ChaCha20-Poly1305 transport, all
	// available through libsodium) is not implemented yet, so we don't touch
	// the tun device or routing table -- we just report it plainly.
	printf("[WireGuard] connect requested for '%s' (endpoint %s:%u) -- "
		"backend not yet implemented\n", profile.fName.String(),
		fConfig.peer.endpointHost.String(),
		(unsigned)fConfig.peer.endpointPort);
	_SetState(VPN_STATE_ERROR, "WireGuard backend not yet implemented");
	return B_ERROR;
}


status_t
WireGuardBackend::Disconnect()
{
	if (fState == VPN_STATE_DISCONNECTED)
		return B_OK;

	fStopRequested = true;
	_Cleanup();
	_SetState(VPN_STATE_DISCONNECTED);
	return B_OK;
}


VPNState
WireGuardBackend::State() const
{
	return fState;
}


VPNStats
WireGuardBackend::Stats() const
{
	return fStats;
}


const char*
WireGuardBackend::BackendName() const
{
	return "WireGuard";
}


BString
WireGuardBackend::LocalIP() const
{
	return fLocalIP;
}


BString
WireGuardBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
WireGuardBackend::MessageReceived(BMessage* message)
{
	switch (message->what) {
		// TODO(wireguard): handshake-retransmit / rekey / keepalive timer
		// ticks (posted by fTimer) and reader-thread events dispatch here.
		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


void
WireGuardBackend::RecoverIfCrashed()
{
	// TODO(wireguard): if a previous run died with a tun slot up and routes
	// installed, roll them back here (mirrors OpenVPNBackend::RecoverIfCrashed).
}


void
WireGuardBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	NotifyStateChanged(state, detail);
}


// --- data plane (TODO(wireguard): implement) -------------------------------

bool
WireGuardBackend::_BringUpTun()
{
	// TODO(wireguard): pick the first free tun/N slot and `ifconfig` it up with
	// fConfig.address, reusing the probe logic in OpenVPNBackend::Connect.
	return false;
}


bool
WireGuardBackend::_OpenUdpSocket()
{
	// TODO(wireguard): resolve fConfig.peer.endpointHost and connect() a UDP
	// socket to it (fConfig.peer.endpointPort); FD_CLOEXEC it like the others.
	return false;
}


bool
WireGuardBackend::_PerformHandshake()
{
	// TODO(wireguard): Noise IK handshake -- initiation + response, deriving
	// the transport keys (Curve25519 / BLAKE2s / ChaCha20-Poly1305 via
	// libsodium). Retransmit the initiation on fTimer until the response lands.
	return false;
}


void
WireGuardBackend::_StartReader()
{
	// TODO(wireguard): spawn _ReaderEntry to forward tun<->UDP once transport
	// keys are live, and post CONNECTED from there.
}


int32
WireGuardBackend::_RunReaderLoop()
{
	// TODO(wireguard): read tun -> encrypt -> UDP, and UDP -> decrypt -> tun,
	// until fStopRequested; post state/stats back to the looper.
	return 0;
}


int32
WireGuardBackend::_ReaderEntry(void* self)
{
	return ((WireGuardBackend*)self)->_RunReaderLoop();
}


void
WireGuardBackend::_Cleanup()
{
	// TODO(wireguard): join the reader thread and tear down tun + routes.
	delete fTimer;
	fTimer = NULL;

	if (fUdpSocket >= 0) {
		close(fUdpSocket);
		fUdpSocket = -1;
	}
}
