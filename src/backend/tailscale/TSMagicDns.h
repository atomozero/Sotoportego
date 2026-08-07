/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_MAGIC_DNS_H
#define TS_MAGIC_DNS_H


#include <stddef.h>
#include <sys/types.h>

#include <String.h>
#include <SupportDefs.h>

#include <utility>
#include <vector>

#include "TSNetmap.h"


// MagicDNS: the stub resolver Tailscale binds at 100.100.100.100. It answers A
// queries for tailnet hostnames (`<host>` or `<host>.<tailnet>.ts.net`) from the
// netmap's peer list with their 100.x addresses, and reports "not mine" for
// everything else so the caller can forward it to the upstream resolvers the
// netmap specifies.
//
// This module owns the DNS message parsing/building (self-contained, no network)
// and the name→address table populated from TSNetmap; the UDP:53 bind and the
// upstream forward live in the backend.
namespace ts {

// Parse the first question of a DNS query: fills `outName` (lowercased dot form,
// no trailing dot), `outType` (QTYPE) and, if non-NULL, `outId`. Returns true on
// a well-formed single-question query. (QNAME compression isn't used in queries.)
bool	DnsParseQuestion(const uint8* buf, size_t len, BString& outName,
			uint16& outType, uint16* outId);

// Build a minimal A-record query for `name` with the given id (for forwarding /
// tests). Returns length or -1.
ssize_t	DnsBuildQuery(const char* name, uint16 id, uint8* out, size_t cap);


class MagicDns {
public:
			void			SetTailnetDomain(const char* domain);	// e.g. "tailXXXX.ts.net"
			void			AddHost(const char* hostname, const char* ipv4);
			void			Clear();

			// Rebuild the host table + tailnet domain from a network map: the
			// domain comes from DNSConfig, and each peer with a hostname maps to
			// its first IPv4 tailnet address (from AllowedIPs). Replaces any
			// previous contents.
			void			LoadFromNetmap(const TSNetmap& nm);

			// Resolve a DNS query. On a match (A record for a known tailnet
			// host) writes the response to `out` and returns its length. Returns
			// 0 if the name isn't ours (caller forwards upstream), -1 on a
			// malformed query.
			ssize_t			Resolve(const uint8* query, size_t qlen, uint8* out,
								size_t cap);

private:
			// Reduce a queried name to a bare tailnet hostname, or "" if it's
			// clearly not in our tailnet.
			BString			_LocalName(const BString& queried) const;

			BString			fDomain;	// tailnet domain, lowercased, no dot
			std::vector<std::pair<BString, BString> >	fHosts;	// name -> ipv4
};

}	// namespace ts


#endif	// TS_MAGIC_DNS_H
