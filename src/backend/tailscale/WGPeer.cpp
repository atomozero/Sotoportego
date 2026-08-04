/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WGPeer.h"

#include <string.h>

#include "WireGuardCrypto.h"


namespace ts {

// RFC 6479 anti-replay window (same parameters as WireGuardBackend).
static const uint64 kReplayBits		= 64;
static const uint64 kReplayBlocks	= 128;		// 8192-bit window
static const uint64 kReplayWindow	= kReplayBits * (kReplayBlocks - 1);
static const uint64 kRejectAfterMessages = 0xFFFFFFFFFFFFFFFFULL
	- (1ULL << 13) - 1;


static void
store32_le(uint8* p, uint32 v)
{
	p[0] = (uint8)v; p[1] = (uint8)(v >> 8);
	p[2] = (uint8)(v >> 16); p[3] = (uint8)(v >> 24);
}


static void
store64_le(uint8* p, uint64 v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (uint8)(v >> (8 * i));
}


static uint64
load64_le(const uint8* p)
{
	uint64 v = 0;
	for (int i = 0; i < 8; i++)
		v |= (uint64)p[i] << (8 * i);
	return v;
}


// Read the real length of an IP packet from its header so the 16-byte-multiple
// WireGuard padding can be stripped. 0 means a keepalive (all padding).
static size_t
ip_packet_length(const uint8* p, size_t maxLen)
{
	if (maxLen == 0)
		return 0;
	uint8 version = p[0] >> 4;
	size_t len = 0;
	if (version == 4 && maxLen >= 20) {
		len = ((size_t)p[2] << 8) | p[3];
	} else if (version == 6 && maxLen >= 40) {
		len = 40 + (((size_t)p[4] << 8) | p[5]);
	} else {
		return 0;
	}
	if (len > maxLen)
		len = maxLen;
	return len;
}


WGPeer::WGPeer()
	:
	fHasKeys(false),
	fReceiverIndex(0),
	fSendCounter(0),
	fReplayCounter(0)
{
	memset(fNodeKey, 0, sizeof(fNodeKey));
	memset(fSendKey, 0, sizeof(fSendKey));
	memset(fRecvKey, 0, sizeof(fRecvKey));
	memset(fReplayBitmap, 0, sizeof(fReplayBitmap));
}


void
WGPeer::SetNodeKey(const uint8 nodeKey[32])
{
	memcpy(fNodeKey, nodeKey, 32);
}


void
WGPeer::SetTransport(const uint8 sendKey[32], const uint8 recvKey[32],
	uint32 receiverIndex)
{
	memcpy(fSendKey, sendKey, 32);
	memcpy(fRecvKey, recvKey, 32);
	fReceiverIndex = receiverIndex;
	fSendCounter = 0;
	fHasKeys = true;
	ResetReplay();
}


size_t
WGPeer::Encapsulate(const uint8* plain, size_t plainLen, uint8* out)
{
	if (!fHasKeys)
		return 0;

	// Pad up to a 16-byte multiple; a keepalive stays at 0 and encrypts to a
	// bare tag.
	size_t padded = (plainLen + 15) & ~(size_t)15;
	uint8 scratch[2048];
	if (padded > sizeof(scratch))
		return 0;
	if (plainLen > 0)
		memcpy(scratch, plain, plainLen);
	memset(scratch + plainLen, 0, padded - plainLen);

	out[0] = 4;
	out[1] = out[2] = out[3] = 0;
	store32_le(out + 4, fReceiverIndex);
	store64_le(out + 8, fSendCounter);
	if (!wg::AeadEncrypt(fSendKey, fSendCounter, scratch, padded, NULL, 0,
			out + 16))
		return 0;
	fSendCounter++;
	return 16 + padded + 16;
}


ssize_t
WGPeer::Decapsulate(const uint8* packet, size_t packetLen, uint8* out)
{
	if (!fHasKeys || packetLen < 32 || packet[0] != 4)
		return -1;
	uint64 counter = load64_le(packet + 8);
	size_t cipherLen = packetLen - 16;
	if (!wg::AeadDecrypt(fRecvKey, counter, packet + 16, cipherLen, NULL, 0,
			out))
		return -1;
	// Enforce anti-replay only after the tag verifies, so forged counters
	// can't poison the window.
	if (!_ReplayValidate(counter))
		return -1;
	size_t plainLen = cipherLen - 16;
	return (ssize_t)ip_packet_length(out, plainLen);
}


void
WGPeer::ResetReplay()
{
	fReplayCounter = 0;
	memset(fReplayBitmap, 0, sizeof(fReplayBitmap));
}


bool
WGPeer::_ReplayValidate(uint64 counter)
{
	if (counter >= kRejectAfterMessages)
		return false;
	counter += 1;	// algorithm is 1-based
	if (kReplayWindow + counter < fReplayCounter)
		return false;

	uint64 index = counter >> 6;
	if (counter > fReplayCounter) {
		uint64 indexCurrent = fReplayCounter >> 6;
		uint64 top = index - indexCurrent;
		if (top > kReplayBlocks)
			top = kReplayBlocks;
		for (uint64 i = 1; i <= top; i++)
			fReplayBitmap[(i + indexCurrent) & (kReplayBlocks - 1)] = 0;
		fReplayCounter = counter;
	}

	index &= (kReplayBlocks - 1);
	uint64 bit = 1ULL << (counter & (kReplayBits - 1));
	if (fReplayBitmap[index] & bit)
		return false;
	fReplayBitmap[index] |= bit;
	return true;
}

}	// namespace ts
