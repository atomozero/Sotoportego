/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_PEER_SET_H
#define TS_PEER_SET_H


#include <String.h>
#include <SupportDefs.h>

#include <vector>

#include "PeerPath.h"
#include "TSNetmap.h"
#include "WGPeer.h"


// The live set of tailnet peers, driven by the network map. Each MapResponse is
// diffed into this set: new peers are added, departed peers removed, and the
// reachability of existing peers (endpoints, AllowedIPs, DERP-home) refreshed --
// so the data plane always mirrors what control last told us. Each peer carries
// a WGPeer (its WireGuard transport, keyed once a handshake completes) plus the
// routing/probing metadata magicsock needs.
namespace ts {

struct ManagedPeer {
	BString					nodeKeyHex;		// 64-hex, the map key
	BString					hostname;
	bool					online;
	int						derpRegion;		// home DERP region id, -1 if none
	std::vector<BString>	allowedIPs;		// CIDRs routed to this peer
	std::vector<BString>	endpoints;		// direct-path candidates
	WGPeer					wg;				// per-peer WireGuard transport
	PeerPath				path;			// DERP-vs-direct send-path state
	bigtime_t				lastHandshake;	// system_time of our last initiation

							ManagedPeer()
								: online(false), derpRegion(-1), lastHandshake(0) {}
};


class TSPeerSet {
public:
							TSPeerSet();

			// Reconcile the peer set against `nm`. Optional out-params receive
			// the number of peers added / removed / updated this round.
			void			Update(const TSNetmap& nm, int* outAdded = NULL,
								int* outRemoved = NULL, int* outUpdated = NULL);

			size_t			Count() const { return fPeers.size(); }
			const std::vector<ManagedPeer>&	Peers() const { return fPeers; }

			// Find a peer by its node key hex (NULL if absent). The pointer is
			// valid only until the next Update().
			ManagedPeer*	Find(const char* nodeKeyHex);

			// Route an outbound packet: find the peer whose AllowedIPs contain
			// the IPv4 destination `ipv4` ("a.b.c.d"), by longest-prefix match
			// (the most specific route wins). NULL if no peer claims it. This is
			// the tun→peer lookup the data-plane reader makes.
			ManagedPeer*	FindByAllowedIP(const char* ipv4);

			// Inbound WireGuard demux: find the peer whose WGPeer sender index
			// (the index we advertised, echoed as the receiver index in the
			// peer's packets to us) equals `index`. NULL / index 0 matches none.
			ManagedPeer*	FindBySenderIndex(uint32 index);

private:
			int				_IndexOf(const BString& hex) const;

			std::vector<ManagedPeer>	fPeers;
};

}	// namespace ts


#endif	// TS_PEER_SET_H
