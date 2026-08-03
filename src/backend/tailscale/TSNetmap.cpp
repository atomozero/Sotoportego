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
TSNetmap::Parse(const char* json, size_t len)
{
	fSelfAddresses.clear();
	fPeers.clear();
	fDerpRegions.clear();
	fDns.resolvers.clear();
	fDns.domains.clear();

	JsonValue root;
	if (!JsonParser::Parse(json, len, root) || !root.IsObject())
		return false;

	// Our own node: Node.Addresses are the tailnet CIDRs to put on the tun.
	const JsonValue* self = root.Find("Node");
	if (self != NULL && self->IsObject()) {
		const JsonValue* addrs = self->Find("Addresses");
		if (addrs != NULL)
			_CollectStrings(addrs, fSelfAddresses);
	}

	// Peers: each carries the WireGuard identity + reachability.
	const JsonValue* peers = root.Find("Peers");
	if (peers != NULL && peers->IsArray()) {
		for (size_t i = 0; i < peers->arrayValue.size(); i++) {
			const JsonValue& pj = peers->arrayValue[i];
			if (!pj.IsObject())
				continue;

			NetmapPeer peer;
			const JsonValue* key = pj.Find("Key");
			if (key != NULL && key->IsString())
				peer.nodeKey = _StripKeyPrefix(key->stringValue.String());
			const JsonValue* disco = pj.Find("DiscoKey");
			if (disco != NULL && disco->IsString())
				peer.discoKey = _StripKeyPrefix(disco->stringValue.String());

			const JsonValue* allowed = pj.Find("AllowedIPs");
			if (allowed != NULL)
				_CollectStrings(allowed, peer.allowedIPs);
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

			// A peer with no key is unusable; skip it.
			if (peer.nodeKey.Length() > 0)
				fPeers.push_back(peer);
		}
	}

	// DERPMap.Regions is a map keyed by region-id strings; each value is a
	// region with a Nodes array of relay servers.
	const JsonValue* derpMap = root.Find("DERPMap");
	if (derpMap != NULL && derpMap->IsObject()) {
		const JsonValue* regions = derpMap->Find("Regions");
		if (regions != NULL && regions->IsObject()) {
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
