/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSMagicDns.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>


namespace ts {

static const size_t kDnsHeaderLen = 12;
static const uint16 kTypeA = 1;
static const uint16 kClassIN = 1;


static BString
to_lower(const BString& s)
{
	BString out(s);
	int32 n = out.Length();
	char* p = out.LockBuffer(n);
	for (int32 i = 0; i < n; i++)
		p[i] = (char)tolower((unsigned char)p[i]);
	out.UnlockBuffer(n);
	return out;
}


// Decode a DNS QNAME (label sequence, no compression) starting at `off` into a
// lowercased dot-joined name. Returns the offset just past the terminating zero,
// or -1 on malformed input.
static ssize_t
decode_qname(const uint8* buf, size_t len, size_t off, BString& outName)
{
	outName = "";
	while (off < len) {
		uint8 labelLen = buf[off++];
		if (labelLen == 0)
			return (ssize_t)off;
		if ((labelLen & 0xc0) != 0)		// compression pointer: not in queries
			return -1;
		if (off + labelLen > len)
			return -1;
		if (outName.Length() > 0)
			outName << '.';
		for (uint8 i = 0; i < labelLen; i++)
			outName << (char)tolower(buf[off + i]);
		off += labelLen;
	}
	return -1;	// ran off the end without a terminator
}


bool
DnsParseQuestion(const uint8* buf, size_t len, BString& outName,
	uint16& outType, uint16* outId)
{
	if (buf == NULL || len < kDnsHeaderLen)
		return false;
	uint16 qdcount = (uint16)((buf[4] << 8) | buf[5]);
	if (qdcount < 1)
		return false;
	if (outId != NULL)
		*outId = (uint16)((buf[0] << 8) | buf[1]);

	ssize_t off = decode_qname(buf, len, kDnsHeaderLen, outName);
	if (off < 0 || (size_t)off + 4 > len)
		return false;
	outType = (uint16)((buf[off] << 8) | buf[off + 1]);
	return true;
}


// Encode a dot name as a DNS QNAME into out; returns bytes written or -1.
static ssize_t
encode_qname(const char* name, uint8* out, size_t cap)
{
	size_t w = 0;
	const char* p = name;
	while (*p != '\0') {
		const char* dot = strchr(p, '.');
		size_t labelLen = dot != NULL ? (size_t)(dot - p) : strlen(p);
		if (labelLen == 0 || labelLen > 63)
			return -1;
		if (w + 1 + labelLen + 1 > cap)
			return -1;
		out[w++] = (uint8)labelLen;
		memcpy(out + w, p, labelLen);
		w += labelLen;
		p += labelLen;
		if (dot != NULL)
			p = dot + 1;
	}
	out[w++] = 0;	// root label
	return (ssize_t)w;
}


ssize_t
DnsBuildQuery(const char* name, uint16 id, uint8* out, size_t cap)
{
	if (cap < kDnsHeaderLen + 5)
		return -1;
	memset(out, 0, kDnsHeaderLen);
	out[0] = (uint8)(id >> 8);
	out[1] = (uint8)(id & 0xff);
	out[2] = 0x01;	// flags: RD
	out[5] = 0x01;	// QDCOUNT = 1
	ssize_t n = encode_qname(name, out + kDnsHeaderLen, cap - kDnsHeaderLen - 4);
	if (n < 0)
		return -1;
	size_t off = kDnsHeaderLen + (size_t)n;
	out[off++] = (uint8)(kTypeA >> 8); out[off++] = (uint8)(kTypeA & 0xff);
	out[off++] = (uint8)(kClassIN >> 8); out[off++] = (uint8)(kClassIN & 0xff);
	return (ssize_t)off;
}


void
MagicDns::SetTailnetDomain(const char* domain)
{
	fDomain = domain != NULL ? to_lower(BString(domain)) : BString("");
}


void
MagicDns::AddHost(const char* hostname, const char* ipv4)
{
	if (hostname == NULL || ipv4 == NULL)
		return;
	fHosts.push_back(std::make_pair(to_lower(BString(hostname)),
		BString(ipv4)));
}


void
MagicDns::Clear()
{
	fHosts.clear();
}


BString
MagicDns::_LocalName(const BString& queried) const
{
	// Accept "<host>" or "<host>.<tailnet-domain>"; strip the domain suffix.
	if (fDomain.Length() > 0) {
		BString suffix(".");
		suffix << fDomain;
		if (queried.EndsWith(suffix)) {
			BString host(queried);
			host.Truncate(queried.Length() - suffix.Length());
			return host;
		}
	}
	// A bare single-label name is treated as a tailnet host too.
	if (queried.FindFirst('.') < 0)
		return queried;
	return BString("");
}


ssize_t
MagicDns::Resolve(const uint8* query, size_t qlen, uint8* out, size_t cap)
{
	BString name;
	uint16 type = 0;
	uint16 id = 0;
	if (!DnsParseQuestion(query, qlen, name, type, &id))
		return -1;
	if (type != kTypeA)
		return 0;	// only A records here; forward others upstream

	BString host = _LocalName(name);
	if (host.Length() == 0)
		return 0;	// not our tailnet -> caller forwards

	BString ip;
	bool found = false;
	for (size_t i = 0; i < fHosts.size(); i++) {
		if (fHosts[i].first == host) {
			ip = fHosts[i].second;
			found = true;
			break;
		}
	}
	if (!found)
		return 0;	// unknown host; let upstream (or NXDOMAIN policy) handle it

	unsigned a, b, c, d;
	if (sscanf(ip.String(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return 0;

	// The question spans from offset 12 to end of QNAME + 4 (qtype+qclass).
	BString tmp;
	ssize_t qEnd = decode_qname(query, qlen, kDnsHeaderLen, tmp);
	if (qEnd < 0)
		return -1;
	size_t questionLen = (size_t)qEnd + 4 - kDnsHeaderLen;

	size_t needed = kDnsHeaderLen + questionLen + 16;	// answer = 16 bytes
	if (cap < needed)
		return -1;

	// Header: copy id, set response flags (QR=1, AA=1, RD from query), 1 answer.
	memset(out, 0, kDnsHeaderLen);
	out[0] = query[0]; out[1] = query[1];
	out[2] = (uint8)(0x84 | (query[2] & 0x01));	// QR|AA + RD bit
	out[3] = 0x00;								// RA=0, RCODE=0
	out[4] = 0x00; out[5] = 0x01;				// QDCOUNT = 1
	out[6] = 0x00; out[7] = 0x01;				// ANCOUNT = 1

	// Question, verbatim.
	memcpy(out + kDnsHeaderLen, query + kDnsHeaderLen, questionLen);
	size_t off = kDnsHeaderLen + questionLen;

	// Answer: name pointer to the question (0xC00C), A/IN, TTL, RDLENGTH 4, IP.
	out[off++] = 0xc0; out[off++] = 0x0c;
	out[off++] = (uint8)(kTypeA >> 8); out[off++] = (uint8)(kTypeA & 0xff);
	out[off++] = (uint8)(kClassIN >> 8); out[off++] = (uint8)(kClassIN & 0xff);
	out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x01; out[off++] = 0x2c;	// TTL 300
	out[off++] = 0x00; out[off++] = 0x04;	// RDLENGTH 4
	out[off++] = (uint8)a; out[off++] = (uint8)b;
	out[off++] = (uint8)c; out[off++] = (uint8)d;

	return (ssize_t)off;
}

}	// namespace ts
