/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSPeerSet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TSIdentity.h"		// FromHex


namespace ts {

TSPeerSet::TSPeerSet()
{
}


int
TSPeerSet::_IndexOf(const BString& hex) const
{
	for (size_t i = 0; i < fPeers.size(); i++) {
		if (fPeers[i].nodeKeyHex == hex)
			return (int)i;
	}
	return -1;
}


ManagedPeer*
TSPeerSet::Find(const char* nodeKeyHex)
{
	if (nodeKeyHex == NULL)
		return NULL;
	int idx = _IndexOf(BString(nodeKeyHex));
	return idx >= 0 ? &fPeers[idx] : NULL;
}


// Parse "a.b.c.d" to a host-order uint32; false on malformed input.
static bool
parse_ipv4(const char* s, uint32& out)
{
	unsigned a, b, c, d;
	if (s == NULL || sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return false;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return false;
	out = (a << 24) | (b << 16) | (c << 8) | d;
	return true;
}


// Parse "a.b.c.d/n" (n optional, default /32). Returns prefix length, or -1.
static int
parse_cidr(const BString& cidr, uint32& network)
{
	BString ipPart(cidr);
	int prefix = 32;
	int slash = ipPart.FindFirst('/');
	if (slash >= 0) {
		prefix = atoi(ipPart.String() + slash + 1);
		ipPart.Truncate(slash);
	}
	if (ipPart.FindFirst(':') >= 0)		// IPv6: not handled here
		return -1;
	if (prefix < 0 || prefix > 32)
		return -1;
	if (!parse_ipv4(ipPart.String(), network))
		return -1;
	return prefix;
}


ManagedPeer*
TSPeerSet::FindBySenderIndex(uint32 index)
{
	if (index == 0)
		return NULL;
	for (size_t i = 0; i < fPeers.size(); i++) {
		if (fPeers[i].wg.SenderIndex() == index)
			return &fPeers[i];
	}
	return NULL;
}


ManagedPeer*
TSPeerSet::FindByDiscoKey(const char* discoKeyHex)
{
	if (discoKeyHex == NULL)
		return NULL;
	BString hex(discoKeyHex);
	for (size_t i = 0; i < fPeers.size(); i++) {
		if (fPeers[i].discoKey == hex && fPeers[i].discoKey.Length() > 0)
			return &fPeers[i];
	}
	return NULL;
}


ManagedPeer*
TSPeerSet::FindByAllowedIP(const char* ipv4)
{
	uint32 dst;
	if (!parse_ipv4(ipv4, dst))
		return NULL;

	ManagedPeer* best = NULL;
	int bestPrefix = -1;
	for (size_t i = 0; i < fPeers.size(); i++) {
		const std::vector<BString>& allowed = fPeers[i].allowedIPs;
		for (size_t j = 0; j < allowed.size(); j++) {
			uint32 net;
			int prefix = parse_cidr(allowed[j], net);
			if (prefix < 0)
				continue;
			// mask = top `prefix` bits (prefix 0 -> match everything).
			uint32 mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
			if (((dst ^ net) & mask) == 0 && prefix > bestPrefix) {
				bestPrefix = prefix;
				best = &fPeers[i];
			}
		}
	}
	return best;
}


void
TSPeerSet::Update(const TSNetmap& nm, int* outAdded, int* outRemoved,
	int* outUpdated)
{
	int added = 0, removed = 0, updated = 0;

	// Mark which existing peers the new map still mentions.
	std::vector<bool> seen(fPeers.size(), false);

	const std::vector<NetmapPeer>& peers = nm.Peers();
	for (size_t i = 0; i < peers.size(); i++) {
		const NetmapPeer& np = peers[i];
		if (np.nodeKey.Length() == 0)
			continue;

		int idx = _IndexOf(np.nodeKey);
		if (idx >= 0) {
			// Existing peer: refresh reachability/metadata (keep its WGPeer +
			// any transport keys already negotiated).
			ManagedPeer& mp = fPeers[idx];
			mp.discoKey = np.discoKey;
			mp.hostname = np.hostname;
			mp.online = np.online;
			mp.derpRegion = np.derpRegion;
			mp.allowedIPs = np.allowedIPs;
			mp.endpoints = np.endpoints;
			if (np.derpRegion >= 0)
				mp.path.UseDerp();
			seen[idx] = true;
			updated++;
		} else {
			// New peer.
			ManagedPeer mp;
			mp.nodeKeyHex = np.nodeKey;
			mp.discoKey = np.discoKey;
			mp.hostname = np.hostname;
			mp.online = np.online;
			mp.derpRegion = np.derpRegion;
			mp.allowedIPs = np.allowedIPs;
			mp.endpoints = np.endpoints;
			uint8 raw[32];
			if (TSIdentity::FromHex(np.nodeKey.String(), raw, 32))
				mp.wg.SetNodeKey(raw);
			if (np.derpRegion >= 0)
				mp.path.UseDerp();
			fPeers.push_back(mp);
			added++;
		}
	}

	// Drop peers the map no longer lists (walk backwards for safe erase).
	for (int i = (int)fPeers.size() - 1; i >= 0; i--) {
		if (i < (int)seen.size() && !seen[i]) {
			fPeers.erase(fPeers.begin() + i);
			removed++;
		}
	}

	if (outAdded != NULL) *outAdded = added;
	if (outRemoved != NULL) *outRemoved = removed;
	if (outUpdated != NULL) *outUpdated = updated;
}

}	// namespace ts
