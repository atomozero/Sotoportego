/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSNetmap.h"

#include <stdlib.h>
#include <string.h>

#include "TSJson.h"


namespace ts {

TSNetmap::TSNetmap()
{
}


BString
TSNetmap::_StripKeyPrefix(const char* key)
{
	// Keys arrive as "nodekey:<hex>" / "discokey:<hex>"; keep just the hex.
	BString s(key);
	int colon = s.FindFirst(':');
	if (colon >= 0)
		s.Remove(0, colon + 1);
	return s;
}


int
TSNetmap::_ParseDerp(const char* derp)
{
	if (derp == NULL || *derp == '\0')
		return -1;
	// Tailscale encodes a node's home DERP as the pseudo-address
	// "127.3.3.40:<region>". Accept that, or a bare integer region.
	const char* colon = strrchr(derp, ':');
	if (colon != NULL)
		return atoi(colon + 1);
	return atoi(derp);
}


void
TSNetmap::_CollectStrings(const void* jsonArray, std::vector<BString>& out)
{
	const JsonValue* arr = (const JsonValue*)jsonArray;
	if (arr == NULL || !arr->IsArray())
		return;
	for (size_t i = 0; i < arr->arrayValue.size(); i++) {
		const JsonValue& v = arr->arrayValue[i];
		if (v.IsString())
			out.push_back(BString(v.stringValue));
	}
}


bool
TSNetmap::_ParsePeer(const void* jsonNode, NetmapPeer& peer)
{
	const JsonValue& pj = *(const JsonValue*)jsonNode;
	if (!pj.IsObject())
		return false;

	const JsonValue* id = pj.Find("ID");
	if (id != NULL)
		peer.nodeID = (int64)id->AsNumber(0);

	const JsonValue* key = pj.Find("Key");
	if (key != NULL && key->IsString())
		peer.nodeKey = _StripKeyPrefix(key->stringValue.String());
	const JsonValue* disco = pj.Find("DiscoKey");
	if (disco != NULL && disco->IsString())
		peer.discoKey = _StripKeyPrefix(disco->stringValue.String());

	const JsonValue* allowed = pj.Find("AllowedIPs");
	if (allowed != NULL)
		_CollectStrings(allowed, peer.allowedIPs);
	// Control often omits AllowedIPs when it equals the node's own Addresses
	// (a plain peer with no subnet routes). Fall back to Addresses so the peer
	// is both routable (FindByAllowedIP) and shows its tailnet IP.
	if (peer.allowedIPs.empty()) {
		const JsonValue* addrs = pj.Find("Addresses");
		if (addrs != NULL)
			_CollectStrings(addrs, peer.allowedIPs);
	}
	const JsonValue* eps = pj.Find("Endpoints");
	if (eps != NULL)
		_CollectStrings(eps, peer.endpoints);

	const JsonValue* derp = pj.Find("DERP");
	if (derp != NULL && derp->IsString())
		peer.derpRegion = _ParseDerp(derp->stringValue.String());

	const JsonValue* online = pj.Find("Online");
	if (online != NULL)
		peer.online = online->AsBool(false);

	const JsonValue* hi = pj.Find("Hostinfo");
	if (hi != NULL && hi->IsObject()) {
		const JsonValue* hn = hi->Find("Hostname");
		if (hn != NULL && hn->IsString())
			peer.hostname = hn->stringValue;
	}

	// A peer with no key is unusable.
	return peer.nodeKey.Length() > 0;
}


void
TSNetmap::_UpsertPeer(const NetmapPeer& peer)
{
	for (size_t i = 0; i < fPeers.size(); i++) {
		bool sameId = peer.nodeID != 0 && fPeers[i].nodeID == peer.nodeID;
		bool sameKey = fPeers[i].nodeKey == peer.nodeKey;
		if (sameId || sameKey) {
			fPeers[i] = peer;
			return;
		}
	}
	fPeers.push_back(peer);
}


bool
TSNetmap::Parse(const char* json, size_t len)
{
	JsonValue root;
	if (!JsonParser::Parse(json, len, root) || !root.IsObject())
		return false;

	// A MapResponse is either a full snapshot or a delta: only the sections
	// actually present are updated, everything else is left as-is. Clearing
	// unconditionally (the old behaviour) wiped the peer set on every keepalive
	// and every delta, so a peer that arrived via "PeersChanged" never stuck.

	// Our own node: Node.Addresses are the tailnet CIDRs to put on the tun.
	const JsonValue* self = root.Find("Node");
	if (self != NULL && self->IsObject()) {
		const JsonValue* addrs = self->Find("Addresses");
		if (addrs != NULL) {
			fSelfAddresses.clear();
			_CollectStrings(addrs, fSelfAddresses);
		}
	}

	// "Peers": a full peer-list snapshot (first response). Replace the set.
	const JsonValue* peers = root.Find("Peers");
	if (peers != NULL && peers->IsArray()) {
		fPeers.clear();
		for (size_t i = 0; i < peers->arrayValue.size(); i++) {
			NetmapPeer peer;
			if (_ParsePeer(&peers->arrayValue[i], peer))
				fPeers.push_back(peer);
		}
	}

	// "PeersChanged": full tailcfg.Node objects for peers that were added or
	// changed (e.g. a device you just joined to the tailnet). Upsert each.
	const JsonValue* changed = root.Find("PeersChanged");
	if (changed != NULL && changed->IsArray()) {
		for (size_t i = 0; i < changed->arrayValue.size(); i++) {
			NetmapPeer peer;
			if (_ParsePeer(&changed->arrayValue[i], peer))
				_UpsertPeer(peer);
		}
	}

	// "PeersChangedPatch": partial updates (NodeID + only the changed fields,
	// typically Endpoints / DERPRegion / Online / Key) for an existing peer.
	const JsonValue* patch = root.Find("PeersChangedPatch");
	if (patch != NULL && patch->IsArray()) {
		for (size_t i = 0; i < patch->arrayValue.size(); i++) {
			const JsonValue& pp = patch->arrayValue[i];
			if (!pp.IsObject())
				continue;
			const JsonValue* nid = pp.Find("NodeID");
			if (nid == NULL)
				continue;
			int64 targetId = (int64)nid->AsNumber(0);
			for (size_t j = 0; j < fPeers.size(); j++) {
				if (fPeers[j].nodeID != targetId)
					continue;
				const JsonValue* eps = pp.Find("Endpoints");
				if (eps != NULL) {
					fPeers[j].endpoints.clear();
					_CollectStrings(eps, fPeers[j].endpoints);
				}
				const JsonValue* derp = pp.Find("DERPRegion");
				if (derp != NULL)
					fPeers[j].derpRegion = (int)derp->AsNumber(fPeers[j].derpRegion);
				const JsonValue* online = pp.Find("Online");
				if (online != NULL)
					fPeers[j].online = online->AsBool(fPeers[j].online);
				const JsonValue* key = pp.Find("Key");
				if (key != NULL && key->IsString())
					fPeers[j].nodeKey = _StripKeyPrefix(key->stringValue.String());
				const JsonValue* disco = pp.Find("DiscoKey");
				if (disco != NULL && disco->IsString())
					fPeers[j].discoKey =
						_StripKeyPrefix(disco->stringValue.String());
				break;
			}
		}
	}

	// "PeersRemoved": array of NodeIDs to drop.
	const JsonValue* removed = root.Find("PeersRemoved");
	if (removed != NULL && removed->IsArray()) {
		for (size_t i = 0; i < removed->arrayValue.size(); i++) {
			int64 gone = (int64)removed->arrayValue[i].AsNumber(0);
			for (size_t j = 0; j < fPeers.size(); j++) {
				if (fPeers[j].nodeID == gone) {
					fPeers.erase(fPeers.begin() + j);
					break;
				}
			}
		}
	}

	// DERPMap.Regions is a map keyed by region-id strings; each value is a
	// region with a Nodes array of relay servers.
	const JsonValue* derpMap = root.Find("DERPMap");
	if (derpMap != NULL && derpMap->IsObject()) {
		const JsonValue* regions = derpMap->Find("Regions");
		if (regions != NULL && regions->IsObject()) {
			fDerpRegions.clear();	// full DERP map when present; replace
			for (size_t i = 0; i < regions->objectValue.size(); i++) {
				const JsonValue& rj = regions->objectValue[i].second;
				if (!rj.IsObject())
					continue;
				DerpRegion region;
				// Region id: prefer the RegionID field, fall back to the map key.
				int keyId = atoi(regions->objectValue[i].first.String());
				const JsonValue* rid = rj.Find("RegionID");
				region.regionID = (rid != NULL)
					? (int)rid->AsNumber(keyId) : keyId;
				const JsonValue* code = rj.Find("RegionCode");
				if (code != NULL && code->IsString())
					region.regionCode = code->stringValue;

				const JsonValue* nodes = rj.Find("Nodes");
				if (nodes != NULL && nodes->IsArray()) {
					for (size_t n = 0; n < nodes->arrayValue.size(); n++) {
						const JsonValue& nj = nodes->arrayValue[n];
						if (!nj.IsObject())
							continue;
						DerpNode node;
						const JsonValue* hn = nj.Find("HostName");
						if (hn != NULL && hn->IsString())
							node.hostName = hn->stringValue;
						const JsonValue* v4 = nj.Find("IPv4");
						if (v4 != NULL && v4->IsString())
							node.ipv4 = v4->stringValue;
						const JsonValue* v6 = nj.Find("IPv6");
						if (v6 != NULL && v6->IsString())
							node.ipv6 = v6->stringValue;
						const JsonValue* port = nj.Find("DERPPort");
						if (port != NULL)
							node.derpPort = (int)port->AsNumber(0);
						region.nodes.push_back(node);
					}
				}
				fDerpRegions.push_back(region);
			}
		}
	}

	// DNSConfig: modern control sends Resolvers ([{Addr}]) + Domains; older
	// snapshots use Nameservers ([addr strings]). Accept both.
	const JsonValue* dns = root.Find("DNSConfig");
	if (dns != NULL && dns->IsObject()) {
		fDns.resolvers.clear();		// full DNS config when present; replace
		fDns.domains.clear();
		const JsonValue* resolvers = dns->Find("Resolvers");
		if (resolvers != NULL && resolvers->IsArray()) {
			for (size_t i = 0; i < resolvers->arrayValue.size(); i++) {
				const JsonValue& r = resolvers->arrayValue[i];
				const JsonValue* addr = r.Find("Addr");
				if (addr != NULL && addr->IsString())
					fDns.resolvers.push_back(BString(addr->stringValue));
			}
		}
		const JsonValue* ns = dns->Find("Nameservers");
		if (ns != NULL)
			_CollectStrings(ns, fDns.resolvers);
		const JsonValue* domains = dns->Find("Domains");
		if (domains != NULL)
			_CollectStrings(domains, fDns.domains);
	}

	return true;
}


const DerpRegion*
TSNetmap::DerpRegionById(int id) const
{
	for (size_t i = 0; i < fDerpRegions.size(); i++) {
		if (fDerpRegions[i].regionID == id)
			return &fDerpRegions[i];
	}
	return NULL;
}


BString
TSNetmap::SelfIPv4() const
{
	for (size_t i = 0; i < fSelfAddresses.size(); i++) {
		const BString& cidr = fSelfAddresses[i];
		// IPv4 tailnet addresses are in 100.64.0.0/10; take the first.
		if (cidr.FindFirst(':') >= 0)
			continue;	// skip IPv6
		BString ip(cidr);
		int slash = ip.FindFirst('/');
		if (slash >= 0)
			ip.Truncate(slash);
		return ip;
	}
	return BString();
}

}	// namespace ts
