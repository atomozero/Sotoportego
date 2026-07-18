/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WIREGUARD_ROUTES_H
#define WIREGUARD_ROUTES_H


#include <vector>

#include <String.h>


// One AllowedIPs entry, resolved to the network + dotted netmask Haiku's
// `route` command wants.
struct AllowedRoute {
	BString	net;			// network address, e.g. "10.2.0.0" or "0.0.0.0"
	BString	mask;			// dotted netmask, e.g. "255.255.255.0"
	bool	isDefault;		// 0.0.0.0/0 -- the full-tunnel catch-all
};


namespace WireGuardRoutes {

// Parse an AllowedIPs list ("10.0.0.0/24, 0.0.0.0/0, ::/0") into IPv4 routes.
//
// IPv6 entries (those containing ':') are NOT routed: they are collected
// verbatim into `skippedV6` instead. This isn't a TODO -- Haiku's tunnel driver
// rejects AF_INET6 (an inet6 address can't be assigned to a tun/N interface,
// verified on device), so IPv6 can't be carried through the tunnel at all. The
// backend logs `skippedV6` so the gap is visible; note that a `::/0` there means
// IPv6 traffic would leak *outside* the tunnel on an IPv6-capable host.
//
// Malformed tokens (empty, bad prefix length) are dropped silently, matching
// the tolerant spirit of the config parser.
void	ParseAllowedIPs(const BString& allowed,
			std::vector<AllowedRoute>& outV4,
			std::vector<BString>& skippedV6);

}	// namespace WireGuardRoutes


#endif	// WIREGUARD_ROUTES_H
