/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WIREGUARD_BACKEND_H
#define WIREGUARD_BACKEND_H


#include <sys/types.h>

#include <OS.h>
#include <String.h>

#include "VPNBackend.h"
#include "WireGuardConfigParser.h"

class BMessageRunner;


// WireGuard backend -- SKELETON.
//
// Unlike OpenVPNBackend, this does not drive an external binary: Haiku has no
// packaged `wg`/wireguard-go, so the plan is an in-process data plane. The
// scaffolding here (config load, state machine, tun/UDP setup, timer hooks) is
// in place; the WireGuard protocol itself is not yet implemented. The pieces
// still to build, all marked with TODO(wireguard) below:
//
//   1. Key material: base64-decode the private/public/preshared keys.
//   2. Data plane: open the tun/N slot we already manage for OpenVPN, bind a
//      UDP socket to the [Peer] Endpoint.
//   3. Handshake: the Noise IK handshake (Curve25519 + BLAKE2s + ChaCha20-
//      Poly1305) -- libsodium (available on HaikuDepot) provides every
//      primitive. Retransmit on a timer until the response lands.
//   4. Transport: encrypt outbound tun reads / decrypt inbound UDP into the
//      tun, on a reader thread; drive rekey (~120s) and PersistentKeepalive
//      via BMessageRunner ticks, mirroring OpenVPNBackend's timers.
//   5. Routing: install AllowedIPs as routes and tear them down on Disconnect,
//      reusing the daemon's routing fix-up.
//
// Until then Connect() loads and validates the config, then reports a clear
// "not yet implemented" error rather than half-configuring the system.
class WireGuardBackend : public VPNBackend {
public:
								WireGuardBackend();
	virtual						~WireGuardBackend();

	virtual	status_t			Connect(const VPNProfile& profile);
	virtual	status_t			Disconnect();
	virtual	VPNState			State() const;
	virtual	VPNStats			Stats() const;
	virtual	const char*			BackendName() const;
	virtual	BString				LocalIP() const;
	virtual	BString				RemoteIP() const;

	virtual	void				MessageReceived(BMessage* message);

	virtual	void				RecoverIfCrashed();

private:
			void				_SetState(VPNState state,
									const char* detail = NULL);

	// --- data plane (TODO(wireguard): implement) -----------------------
	// Bring up the first free tun/N slot and assign the [Interface] Address.
	// The slot-probe logic can be shared with OpenVPNBackend once factored
	// out; stubbed for the skeleton.
			bool				_BringUpTun();
	// Bind a UDP socket toward the [Peer] Endpoint.
			bool				_OpenUdpSocket();
	// Run the Noise IK handshake. Returns true once transport keys are set.
			bool				_PerformHandshake();
	// Reader thread: tun<->UDP forwarding once the handshake completes.
			void				_StartReader();
			int32				_RunReaderLoop();
	static	int32				_ReaderEntry(void* self);
	// Tear everything down: threads, socket, tun slot, routes.
			void				_Cleanup();

			VPNState			fState;
			VPNStats			fStats;
			WireGuardConfig		fConfig;
			BString				fLocalIP;		// in-tunnel Address
			BString				fRemoteIP;		// Endpoint host

	// Haiku tunnel slot, picked at Connect time (see OpenVPNBackend for the
	// probing rationale). "tun/N" for ifconfig/route, "/dev/tun/N" for the node.
			BString				fTunInterface;
			BString				fTunNode;

			int					fUdpSocket;		// -1 when none
			thread_id			fReader;		// -1 when no thread alive
	// Handshake-retransmit / rekey / keepalive timer. NULL when idle.
			BMessageRunner*		fTimer;
			bool				fStopRequested;
};


#endif	// WIREGUARD_BACKEND_H
