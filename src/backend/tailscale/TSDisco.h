/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_DISCO_H
#define TS_DISCO_H


#include <stddef.h>
#include <sys/types.h>

#include <String.h>
#include <SupportDefs.h>


// Tailscale's `disco` protocol -- the peer-to-peer messages magicsock exchanges
// over UDP (directly and via DERP) to discover a working direct path and keep it
// alive. Every disco packet is:
//
//     Magic (6 bytes: "TS💬" = 54 53 f0 9f 92 ac)
//     senderDiscoPublic (32 bytes)
//     nonce (24 bytes)
//     NaCl box(payload)      -- sealed to the recipient's disco key
//
// The plaintext payload is a small message: a 2-byte header (type + version=0)
// followed by type-specific fields. Ping/Pong drive the path probe; CallMeMaybe
// advertises our candidate endpoints. All sealing uses NaClBox with the disco
// keys (kept separate from the node key so probing can't be correlated).
namespace ts {

static const size_t kDiscoMagicLen	= 6;
static const size_t kDiscoKeyLen	= 32;
static const size_t kDiscoNonceLen	= 24;
static const size_t kDiscoHeaderOff	= kDiscoMagicLen + kDiscoKeyLen
										+ kDiscoNonceLen;	// 62
static const size_t kDiscoMsgHeaderLen = 2;					// type + version
static const size_t kDiscoTxIDLen	= 12;

enum DiscoType {
	DISCO_PING			= 0x01,
	DISCO_PONG			= 0x02,
	DISCO_CALLMEMAYBE	= 0x03
};

struct DiscoPing {
	uint8	txid[12];
	uint8	nodeKey[32];
	bool	hasNodeKey;

			DiscoPing() : hasNodeKey(false) {}
};

struct DiscoPong {
	uint8	txid[12];
	BString	srcIP;		// "a.b.c.d" the responder saw the ping come from
	uint16	srcPort;

			DiscoPong() : srcPort(0) {}
};


// --- payload (plaintext message) codecs ------------------------------------

// Encode a Ping. If nodeKey != NULL it is appended (recommended). Returns len.
size_t	EncodePing(uint8* out, const uint8 txid[12], const uint8* nodeKey);
// Encode a Pong echoing txid and the observed source ip:port. Returns len.
size_t	EncodePong(uint8* out, const uint8 txid[12], const char* srcIP,
			uint16 srcPort);

// The disco message type of a plaintext payload (0 if too short).
uint8	DiscoMessageType(const uint8* msg, size_t len);
bool	DecodePing(const uint8* msg, size_t len, DiscoPing& out);
bool	DecodePong(const uint8* msg, size_t len, DiscoPong& out);


// --- packet framing (seal/open the NaCl box + magic header) ----------------

// Seal a plaintext disco `payload` into a full packet in `out`. Uses a fresh
// random nonce; boxes to `peerDiscoPub` from `senderDiscoPriv`. Returns the
// packet length, or -1 if it doesn't fit.
ssize_t	DiscoSeal(uint8* out, size_t outCap, const uint8 senderDiscoPub[32],
			const uint8 senderDiscoPriv[32], const uint8 peerDiscoPub[32],
			const uint8* payload, size_t payloadLen);

// Parse and decrypt a received disco packet with our disco private key. On
// success writes the sender's disco public key to `outSenderPub` and the
// plaintext to `outPayload`, returning the plaintext length. -1 on bad magic /
// short packet / auth failure.
ssize_t	DiscoOpen(const uint8* packet, size_t len, const uint8 myDiscoPriv[32],
			uint8 outSenderPub[32], uint8* outPayload, size_t outCap);

}	// namespace ts


#endif	// TS_DISCO_H
