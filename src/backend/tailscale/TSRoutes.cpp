/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSRoutes.h"

#include <stdio.h>

#include "WireGuardRoutes.h"


namespace ts {

// The tailnet CGNAT range 100.64.0.0/10: network 0x64400000, mask 0xFFC00000.
static const uint32 kTailnetNet		= 0x64400000u;
static const uint32 kTailnetMask	= 0xFFC00000u;


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


static bool
contains(const std::vector<SubnetRoute>& v, const SubnetRoute& r)
{
	for (size_t i = 0; i < v.size(); i++) {
		if (v[i] == r)
			return true;
	}
	return false;
}


void
ComputeSubnetRoutes(const std::vector<BString>& allowedIPs,
	std::vector<SubnetRoute>& out)
{
	out.clear();
	for (size_t i = 0; i < allowedIPs.size(); i++) {
		std::vector<AllowedRoute> v4;
		std::vector<BString> v6;	// IPv6 skipped by the parser
		WireGuardRoutes::ParseAllowedIPs(allowedIPs[i], v4, v6);

		for (size_t j = 0; j < v4.size(); j++) {
			const AllowedRoute& c = v4[j];
			// The default route is an exit node -- not installed here.
			if (c.isDefault)
				continue;
			uint32 net = 0;
			if (!parse_ipv4(c.net.String(), net))
				continue;
			// Anything inside the tailnet CGNAT block is already on-link.
			if ((net & kTailnetMask) == kTailnetNet)
				continue;
			SubnetRoute r;
			r.net = c.net;
			r.mask = c.mask;
			if (!contains(out, r))
				out.push_back(r);
		}
	}
}


void
DiffRoutes(const std::vector<SubnetRoute>& desired,
	const std::vector<SubnetRoute>& installed,
	std::vector<SubnetRoute>& toAdd, std::vector<SubnetRoute>& toRemove)
{
	toAdd.clear();
	toRemove.clear();
	for (size_t i = 0; i < desired.size(); i++) {
		if (!contains(installed, desired[i]))
			toAdd.push_back(desired[i]);
	}
	for (size_t i = 0; i < installed.size(); i++) {
		if (!contains(desired, installed[i]))
			toRemove.push_back(installed[i]);
	}
}


static bool
contains_ip(const std::vector<BString>& v, const BString& ip)
{
	for (size_t i = 0; i < v.size(); i++) {
		if (v[i] == ip)
			return true;
	}
	return false;
}


void
ComputeExitCarveouts(const std::vector<BString>& underlayIPs,
	std::vector<BString>& out)
{
	out.clear();
	for (size_t i = 0; i < underlayIPs.size(); i++) {
		const BString& ip = underlayIPs[i];
		uint32 parsed = 0;
		if (ip.Length() == 0 || !parse_ipv4(ip.String(), parsed))
			continue;	// empty or non-IPv4 (e.g. an IPv6 or DERP hostname)
		if (!contains_ip(out, ip))
			out.push_back(ip);
	}
}


void
DiffCarveouts(const std::vector<BString>& desired,
	const std::vector<BString>& pinned,
	std::vector<BString>& toAdd, std::vector<BString>& toRemove)
{
	toAdd.clear();
	toRemove.clear();
	for (size_t i = 0; i < desired.size(); i++) {
		if (!contains_ip(pinned, desired[i]))
			toAdd.push_back(desired[i]);
	}
	for (size_t i = 0; i < pinned.size(); i++) {
		if (!contains_ip(desired, pinned[i]))
			toRemove.push_back(pinned[i]);
	}
}

}	// namespace ts
