/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TAILSCALE_BACKEND_H
#define TAILSCALE_BACKEND_H


#include <Locker.h>
#include <OS.h>
#include <String.h>

#include "VPNBackend.h"
#include "VPNStats.h"

#include "MagicSock.h"
#include "TSDerp.h"
#include "TSIdentity.h"
#include "TSSessionState.h"

namespace ts { class ControlSession; }


// Tailscale backend -- full, in-process Tailscale ("level C"), built from
// scratch the same way WireGuardBackend was (Haiku has no packaged tailscaled).
//
// This is the Phase 0 scaffold: it satisfies the VPNBackend seam so the daemon
// can construct and select it, but Connect() only reports that the backend is
// not implemented yet. The real machinery -- the ts2021 control channel, the
// network-map long poll, magicsock (STUN + disco + direct paths), the DERP
// relay client and MagicDNS -- lands phase by phase per design/tailscale/.
//
// The data plane reuses the existing WireGuard transport (WireGuardCrypto +
// the WGPeer unit factored out in Phase 3); what is new here is everything that
// decides who the peers are and how packets reach them. See
// design/tailscale/DESIGN.md for the architecture and ROADMAP.md for the plan.
//
// Threading, once implemented, mirrors the other backends: all state mutation
// happens on the daemon looper, and worker threads (control, magicsock reader,
// DERP reader, tun reader) post results back via BMessenger(this).
class TailscaleBackend : public VPNBackend {
public:
								TailscaleBackend();
	virtual						~TailscaleBackend();

	virtual	status_t			Connect(const VPNProfile& profile);
	virtual	status_t			Disconnect();
	virtual	VPNState			State() const;
	virtual	VPNStats			Stats() const;
	virtual	const char*			BackendName() const;
	virtual	BString				LocalIP() const;
	virtual	BString				RemoteIP() const;
	virtual	void				FillPeers(BMessage& out);

	virtual	void				MessageReceived(BMessage* message);

	virtual	void				RecoverIfCrashed();

private:
			void				_SetState(VPNState state,
									const char* detail = NULL);

	// Control worker: runs the ts2021 handshake + registration off the looper,
	// posting AuthURL / authorized / failed back via BMessenger(this). It never
	// mutates backend state directly.
			void				_StartWorker();
	static	int32				_WorkerEntry(void* self);
			int32				_RunControlFlow();
	// After authorization, long-poll the network map on the session's HTTP/2
	// connection, applying each MapResponse to fSession and posting netmap
	// summaries back to the looper. Returns when stopped or the stream ends.
			void				_RunMap(ts::ControlSession& session,
										BMessenger& self);
			void				_StopWorker();

	// Bring up a tun/N slot and assign our tailnet IPv4 (/10 CGNAT) to it, once
	// the first netmap gives us a self address; _TeardownTun removes it.
			void				_BringUpTun(const char* selfIPv4);
			void				_TeardownTun();
	// Open the magicsock UDP socket and learn our public endpoint via a DERP
	// STUN server from the netmap. Runs on the worker thread (STUN blocks).
			void				_BringUpMagicSock(BMessenger& self);

	// The packet data plane: two reader threads move IP packets between the tun
	// device and the peers over magicsock (WireGuard type-4), lazily running a
	// per-peer handshake on first traffic and choosing the send path. Access to
	// the peer set is guarded by fSessionLock (the map worker mutates it).
			void				_StartDataPlane();
			void				_StopDataPlane();
	static	int32				_TunReaderEntry(void* self);
	static	int32				_SockReaderEntry(void* self);
	static	int32				_DerpReaderEntry(void* self);
			int32				_RunTunReader();
			int32				_RunSockReader();
			int32				_RunDerpReader();
	// Connect the DERP relay for the netmap's home region (a fallback path when
	// no direct route exists). Runs on the worker.
			void				_BringUpDerp();
	// Tell control our home DERP region (endpoint "127.3.3.40:<region>") plus
	// our LAN endpoint, via a one-shot MapRequest on a second connection, so
	// peers get a return path to us over the relay. Runs on the worker after
	// _BringUpDerp.
			void				_AdvertiseDerpHome(const char* lanEndpoint);
	// Demux one raw WireGuard packet (from magicsock or DERP): a handshake
	// response completes the session; a type-4 data message decrypts to the tun.
			void				_HandleWireGuardPacket(const uint8* buf,
									size_t len);
	// Handle an inbound disco packet: answer a ping with a pong; on a pong,
	// upgrade the peer's path to the direct address it arrived from.
			void				_HandleDiscoPacket(const uint8* buf, size_t len,
									const struct sockaddr_in& from);
	// Probe a peer's candidate endpoints with a disco ping (throttled), so a
	// returning pong can upgrade its path off DERP. Caller holds fSessionLock.
			void				_SendDiscoPing(ts::ManagedPeer* peer);

	// MagicDNS: a UDP:53 resolver bound to our tailnet address that answers
	// tailnet names from the netmap and forwards the rest to an upstream.
			void				_StartMagicDns();
			void				_StopMagicDns();
	static	int32				_DnsEntry(void* self);
			int32				_RunDnsServer();
	// Encapsulate + send `packet` to `peer` on its current path (direct UDP for
	// now); lazily initiates a handshake if the peer has no transport keys yet.
	// Caller holds fSessionLock.
			void				_SendToPeer(ts::ManagedPeer* peer,
									const uint8* packet, size_t len);
	// Send raw WireGuard bytes to a peer over its best path (direct or DERP).
			void				_SendPeerBytes(ts::ManagedPeer* peer,
									const uint8* buf, size_t len);

			VPNState			fState;
			VPNStats			fStats;
			BString				fLocalIP;	// our 100.x tailnet address
			BString				fRemoteIP;	// control/DERP endpoint summary

			// Persistent machine/node/disco keypairs, loaded-or-created on the
			// first Connect and reused across the session (and across restarts,
			// via the keystore). See TSIdentity.
			ts::TSIdentity		fIdentity;

			// Connect() snapshots what the worker needs so the thread never
			// touches the (caller-owned) VPNProfile.
			BString				fControlHost;
			BString				fHostname;
			BString				fAuthKey;

			thread_id			fWorker;		// -1 when none
			volatile bool		fStopRequested;	// set from another thread

			// The netmap-derived data-plane state, updated by the map loop.
			ts::SessionState	fSession;

			// Haiku tun slot once brought up: "tun/N" and "/dev/tun/N".
			BString				fTunInterface;
			BString				fTunNode;

			// The magicsock UDP socket (worker-owned) and our discovered public
			// endpoint.
			ts::MagicSock		fMagicSock;

			// Data-plane: the tun fd and the two reader threads, plus a lock
			// guarding fSession against the concurrent map worker.
			int					fTunFd;			// /dev/tun/N, -1 when none
			thread_id			fTunReader;		// -1 when none
			thread_id			fSockReader;	// -1 when none
			thread_id			fDerpReader;	// -1 when none
			int					fDnsFd;			// MagicDNS UDP:53, -1 when none
			thread_id			fDnsThread;		// -1 when none
			BLocker				fSessionLock;

			// DERP relay for the home region (fallback path).
			ts::DerpClient		fDerp;
			bool				fDerpUp;
			int					fDerpHomeRegion;	// -1 until connected
};


#endif	// TAILSCALE_BACKEND_H
