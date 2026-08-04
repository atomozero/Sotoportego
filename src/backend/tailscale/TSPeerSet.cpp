/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSPeerSet.h"

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
			mp.hostname = np.hostname;
			mp.online = np.online;
			mp.derpRegion = np.derpRegion;
			mp.allowedIPs = np.allowedIPs;
			mp.endpoints = np.endpoints;
			seen[idx] = true;
			updated++;
		} else {
			// New peer.
			ManagedPeer mp;
			mp.nodeKeyHex = np.nodeKey;
			mp.hostname = np.hostname;
			mp.online = np.online;
			mp.derpRegion = np.derpRegion;
			mp.allowedIPs = np.allowedIPs;
			mp.endpoints = np.endpoints;
			uint8 raw[32];
			if (TSIdentity::FromHex(np.nodeKey.String(), raw, 32))
				mp.wg.SetNodeKey(raw);
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
