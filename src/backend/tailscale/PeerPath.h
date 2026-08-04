/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef PEER_PATH_H
#define PEER_PATH_H


#include <String.h>
#include <SupportDefs.h>


// Per-peer send-path state implementing Tailscale's "DERP-then-upgrade" policy:
// a peer is reachable via its home DERP relay from t=0 (so traffic flows
// immediately), while disco pings probe its candidate endpoints in parallel;
// when a disco pong confirms a working direct UDP endpoint the path upgrades to
// that direct address and stops relaying, and if the direct path then goes quiet
// it falls back to DERP. This is the pure decision state; the actual sending is
// magicsock's job.
namespace ts {

enum PathMode {
	PATH_NONE	= 0,	// nothing usable yet
	PATH_DERP	= 1,	// relay via the home DERP region
	PATH_DIRECT	= 2		// direct UDP to a hole-punched endpoint
};


class PeerPath {
public:
							PeerPath();

			// The peer is reachable via DERP (call once the netmap gives it a
			// home region). Never downgrades an already-direct path.
			void			UseDerp();

			// A disco pong confirmed `endpoint` ("ip:port") works: upgrade to
			// the direct path as of `now`.
			void			UpgradeToDirect(const char* endpoint, bigtime_t now);

			// Record inbound traffic on the current direct path (keepalive/data)
			// so it isn't considered stale.
			void			NoteDirectActivity(bigtime_t now);

			// Decide the send path now, downgrading DIRECT→DERP if the direct
			// path has been silent longer than `staleAfterUs`.
			PathMode		Evaluate(bigtime_t now, bigtime_t staleAfterUs);

			PathMode		Mode() const { return fMode; }
			const BString&	DirectEndpoint() const { return fEndpoint; }

private:
			PathMode		fMode;
			BString			fEndpoint;
			bigtime_t		fLastDirectActivity;
};

}	// namespace ts


#endif	// PEER_PATH_H
