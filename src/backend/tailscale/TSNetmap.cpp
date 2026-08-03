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

	return true;
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
