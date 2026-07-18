/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WireGuardRoutes.h"

#include <stdlib.h>


void
WireGuardRoutes::ParseAllowedIPs(const BString& allowed,
	std::vector<AllowedRoute>& outV4, std::vector<BString>& skippedV6)
{
	int32 start = 0;
	while (start <= allowed.Length()) {
		int32 comma = allowed.FindFirst(',', start);
		int32 end = (comma < 0) ? allowed.Length() : comma;
		BString token;
		allowed.CopyInto(token, start, end - start);
		token.Trim();
		start = end + 1;
		if (token.Length() == 0)
			continue;
		// IPv6 (contains ':'): can't be routed through Haiku's tun (no
		// AF_INET6). Record it so the caller can warn rather than drop silently.
		if (token.FindFirst(':') >= 0) {
			skippedV6.push_back(token);
			continue;
		}

		BString net = token;
		int prefix = 32;
		int32 slash = token.FindFirst('/');
		if (slash >= 0) {
			net.Truncate(slash);
			BString p;
			token.CopyInto(p, slash + 1, token.Length() - slash - 1);
			prefix = atoi(p.String());
		}
		net.Trim();
		if (net.Length() == 0 || prefix < 0 || prefix > 32)
			continue;

		uint32 m = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
		AllowedRoute c;
		c.net = net;
		c.mask.SetToFormat("%u.%u.%u.%u", (m >> 24) & 0xFF, (m >> 16) & 0xFF,
			(m >> 8) & 0xFF, m & 0xFF);
		c.isDefault = (net == "0.0.0.0" && prefix == 0);
		outV4.push_back(c);
	}
}
