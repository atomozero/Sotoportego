/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_NETMAP_H
#define TS_NETMAP_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>

#include <vector>


// The parsed network map: the single source of truth for the data plane. A
// MapResponse (JSON) is turned into our own tailnet addresses plus the set of
// peers, each with the WireGuard identity and reachability info the transport
// and magicsock need. This revision extracts the essentials (self addresses and
// per-peer key/disco/endpoints/DERP/AllowedIPs/name); DNSConfig and the full
// DERPMap are layered on next.
namespace ts {

struct NetmapPeer {
	BString					nodeKey;	// hex, "nodekey:" prefix stripped
	BString					discoKey;	// hex, "discokey:" prefix stripped
	BString					hostname;
	bool					online;
	int						derpRegion;	// home DERP region id, -1 if unknown
	std::vector<BString>	allowedIPs;	// CIDR strings
	std::vector<BString>	endpoints;	// "ip:port" direct-path candidates

							NetmapPeer() : online(false), derpRegion(-1) {}
};


class TSNetmap {
public:
							TSNetmap();

			// Parse a MapResponse JSON document, replacing this netmap's
			// contents. Returns true on a well-formed document.
			bool			Parse(const char* json, size_t len);

			const std::vector<BString>&	SelfAddresses() const
									{ return fSelfAddresses; }
			const std::vector<NetmapPeer>&	Peers() const { return fPeers; }

			// Our first IPv4 tailnet address (100.64.0.0/10) without the /32,
			// or empty if none. This is what goes on the tun interface.
			BString			SelfIPv4() const;

private:
	static	void			_CollectStrings(const void* jsonArray,
								std::vector<BString>& out);
	// Parse "127.3.3.40:<region>" (Tailscale's DERP-home encoding) or a bare
	// region number into a region id; -1 if not recognised.
	static	int				_ParseDerp(const char* derp);
	static	BString			_StripKeyPrefix(const char* key);

			std::vector<BString>		fSelfAddresses;
			std::vector<NetmapPeer>		fPeers;
};

}	// namespace ts


#endif	// TS_NETMAP_H
