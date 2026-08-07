/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_ROUTES_H
#define TS_ROUTES_H


#include <String.h>
#include <SupportDefs.h>

#include <vector>


// Subnet-route planning for the Tailscale data plane. A tailnet peer can be a
// *subnet router* -- it advertises non-tailnet CIDRs in its AllowedIPs (e.g.
// 192.168.1.0/24) that it will forward for. For the kernel to hand those packets
// to our tun (where the peer-set demux routes them to the right peer), we must
// install a system route per such CIDR onto the tun interface.
//
// The tailnet CGNAT range (100.64.0.0/10) is already on-link via the tun's own
// /10 address, so it needs no extra route; the default route (0.0.0.0/0, an exit
// node) is deliberately NOT auto-installed here -- full-tunnel routing needs the
// control/DERP carve-outs handled separately. IPv6 can't ride Haiku's tun.
//
// This logic is factored out (pure, no I/O) so it can be unit-tested; the backend
// turns the result into `route add/delete` calls and reconciles across netmaps.
namespace ts {

struct SubnetRoute {
	BString	net;	// network address, e.g. "192.168.1.0"
	BString	mask;	// dotted netmask, e.g. "255.255.255.0"

	bool operator==(const SubnetRoute& o) const
		{ return net == o.net && mask == o.mask; }
};


// Compute the deduplicated set of IPv4 subnet routes to install for the given
// peer AllowedIP CIDRs. Excludes the tailnet /10 (already on-link), the default
// route (exit node), and IPv6.
void ComputeSubnetRoutes(const std::vector<BString>& allowedIPs,
		std::vector<SubnetRoute>& out);

// Reconcile a desired route set against the currently installed one: fill
// `toAdd` with routes in `desired` but not `installed`, and `toRemove` with
// routes in `installed` but no longer `desired`.
void DiffRoutes(const std::vector<SubnetRoute>& desired,
		const std::vector<SubnetRoute>& installed,
		std::vector<SubnetRoute>& toAdd, std::vector<SubnetRoute>& toRemove);

}	// namespace ts


#endif	// TS_ROUTES_H
