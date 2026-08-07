/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_BACKEND_H
#define VPN_BACKEND_H


#include <Handler.h>
#include <Messenger.h>
#include <String.h>

#include "VPNProfile.h"
#include "VPNState.h"
#include "VPNStats.h"

class BMessage;


// Abstract interface every VPN implementation (OpenVPN, WireGuard, IPSec, ...)
// must satisfy. A backend is owned by the daemon and lives inside the daemon's
// BLooper, so it derives from BHandler: that lets it receive its own timer
// (BMessageRunner) ticks and other async events via MessageReceived(), without
// each backend having to invent its own threading.
//
// Route and DNS management are deliberately NOT part of this interface: they
// will be a shared service of the daemon (see Milestone 2), invoked the same
// way regardless of backend, rather than reimplemented per backend.
//
// Threading: all methods are expected to be called from the daemon's looper
// thread (i.e. with the looper locked, as is the case inside MessageReceived).
class VPNBackend : public BHandler {
public:
								VPNBackend(const char* name);
	virtual						~VPNBackend();

	// Begin connecting using the given profile. Returns immediately; progress
	// is reported asynchronously through the observer as state changes. It is
	// an error to call Connect() while not Disconnected.
	virtual	status_t			Connect(const VPNProfile& profile) = 0;

	// Begin tearing down the connection. Returns immediately; completion is
	// reported as a transition to VPN_STATE_DISCONNECTED.
	virtual	status_t			Disconnect() = 0;

	virtual	VPNState			State() const = 0;
	virtual	VPNStats			Stats() const = 0;

	// Tunnel addresses, valid once the session reaches CONNECTED. The
	// defaults are empty strings; backends that know better override them.
	virtual	BString				LocalIP() const { return BString(); }
	virtual	BString				RemoteIP() const { return BString(); }

	// Fold the current peer list into a status message (one nested kFieldPeer
	// per peer). Only meshy backends (Tailscale) have peers; the default is a
	// no-op.
	virtual	void				FillPeers(BMessage& /*out*/) {}

	// Provide transient credentials for the next connection attempt; the
	// default is a no-op for backends that don't need them. Plaintext and
	// not persisted.
	virtual	void				SetCredentials(const BString& /*user*/,
									const BString& /*pass*/) {}

	// Route all traffic through a peer acting as an exit node, identified by an
	// opaque backend-specific id (empty string clears it). Only meshy backends
	// (Tailscale) support this; the default reports it isn't supported.
	virtual	status_t			SetExitNode(const BString& /*id*/)
									{ return B_NOT_SUPPORTED; }

	// Called once at daemon startup. Backends that touch routing or other
	// system state during a session can override this to roll back any
	// mess left over by a previous crashed run. Default is a no-op.
	virtual	void				RecoverIfCrashed() {}

	// A short, stable identifier for this backend ("OpenVPN", ...). Distinct
	// from BHandler::Name().
	virtual	const char*			BackendName() const = 0;

	// Designate the BMessenger that should receive asynchronous state and
	// stats events (typically the daemon itself). Replaces any previous
	// observer. Passing an invalid messenger silences events.
	virtual	void				SetObserver(const BMessenger& observer);

protected:
	// Helpers for subclasses to publish events to the observer. These build
	// the standard kMsgStatusUpdate / kMsgStatsUpdate messages and are no-ops
	// when no valid observer is set.
			void				NotifyStateChanged(VPNState state,
									const char* detail = NULL);
			void				NotifyStats(const VPNStats& stats);

			BMessenger			fObserver;
};


#endif	// VPN_BACKEND_H
