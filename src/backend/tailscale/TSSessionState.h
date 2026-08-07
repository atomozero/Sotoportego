/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_SESSION_STATE_H
#define TS_SESSION_STATE_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>

#include "TSMagicDns.h"
#include "TSNetmap.h"
#include "TSPeerSet.h"


// The data-plane view of a tailnet session, updated on every MapResponse. It
// bundles the three netmap-derived pieces the backend keeps in sync -- the
// parsed netmap, the live peer set (WGPeer per peer), and the MagicDNS host
// table -- plus our own tailnet IPv4. `ApplyMapResponse` is the single handler
// the map long-poll calls for each streamed message, so the whole data plane
// re-derives from one place.
namespace ts {

class SessionState {
public:
							SessionState();

			// Parse a MapResponse JSON and re-derive the peer set, MagicDNS
			// table and self address from it. Returns true on a well-formed
			// document; `outAdded/Removed/Updated` (optional) report the peer
			// diff for logging.
			bool			ApplyMapResponse(const char* json, size_t len,
								int* outAdded = NULL, int* outRemoved = NULL,
								int* outUpdated = NULL);

			const TSNetmap&	Netmap() const { return fNetmap; }
			TSPeerSet&		Peers() { return fPeers; }
			MagicDns&		Dns() { return fDns; }
			const BString&	SelfIPv4() const { return fSelfIP; }
			int				PeerCount() const { return (int)fPeers.Count(); }

private:
			TSNetmap		fNetmap;
			TSPeerSet		fPeers;
			MagicDns		fDns;
			BString			fSelfIP;
};

}	// namespace ts


#endif	// TS_SESSION_STATE_H
