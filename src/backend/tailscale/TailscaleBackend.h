/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TAILSCALE_BACKEND_H
#define TAILSCALE_BACKEND_H


#include <OS.h>
#include <String.h>

#include "VPNBackend.h"
#include "VPNStats.h"

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
			bool				fStopRequested;

			// The netmap-derived data-plane state, updated by the map loop.
			ts::SessionState	fSession;
};


#endif	// TAILSCALE_BACKEND_H
