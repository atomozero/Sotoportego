/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_STUN_H
#define TS_STUN_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>


// Minimal STUN (RFC 5389) binding client. magicsock sends a binding request to a
// DERP server's STUN service to learn the public ip:port the outside world sees
// for our UDP socket -- that pair becomes one of the "endpoints" we report to
// the control server for other peers to hole-punch toward.
//
// Only what's needed is implemented: a binding request and parsing the success
// response's XOR-MAPPED-ADDRESS (falling back to MAPPED-ADDRESS), IPv4 for now
// (in-tunnel IPv6 is out of scope on Haiku; the STUN underlay stays v4).
namespace ts {

static const size_t kStunHeaderLen	= 20;
static const uint32 kStunMagicCookie = 0x2112a442;

// Build a 20-byte binding request into `out`, filling `txId` (12 bytes) with a
// fresh random transaction id the caller keeps to match the response.
void	StunBuildRequest(uint8 out[20], uint8 txId[12]);

// Parse a STUN response. On a binding-success response whose transaction id
// matches `txId`, set `outIP` ("a.b.c.d") and `outPort` and return true.
bool	StunParseResponse(const uint8* buf, size_t len, const uint8 txId[12],
			BString& outIP, uint16& outPort);

// Convenience: resolve `host`, send a binding request over UDP to host:port,
// and return the reflected public ip:port. Blocking with a short timeout.
// Returns B_OK on success.
status_t StunQuery(const char* host, uint16 port, BString& outIP,
			uint16& outPort);

}	// namespace ts


#endif	// TS_STUN_H
