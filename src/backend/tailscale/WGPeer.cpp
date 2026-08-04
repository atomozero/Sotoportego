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


static uint32
load32_le(const uint8* p)
{
	return (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
}


// h = HASH(h || data)
static void
mix_hash(uint8 h[32], const void* data, size_t len)
{
	wg::Blake2s s;
	wg::HashInit(s);
	wg::HashUpdate(s, h, 32);
	if (len > 0)
		wg::HashUpdate(s, data, len);
	wg::HashFinal(s, h);
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
	fReplayCounter(0),
	fSenderIndex(0)
{
	memset(fNodeKey, 0, sizeof(fNodeKey));
	memset(fSendKey, 0, sizeof(fSendKey));
	memset(fRecvKey, 0, sizeof(fRecvKey));
	memset(fReplayBitmap, 0, sizeof(fReplayBitmap));
	memset(fOurPriv, 0, sizeof(fOurPriv));
	memset(fPeerStatic, 0, sizeof(fPeerStatic));
	memset(fEphemeralPriv, 0, sizeof(fEphemeralPriv));
	memset(fEphemeralPub, 0, sizeof(fEphemeralPub));
	memset(fChainingKey, 0, sizeof(fChainingKey));
	memset(fHash, 0, sizeof(fHash));
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


// WireGuard IKpsk2 handshake labels (see the protocol spec).
static const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const uint8 kLabelMac1[8] = { 'm', 'a', 'c', '1', '-', '-', '-', '-' };


ssize_t
WGPeer::BuildInitiation(const uint8 ourPriv[32], const uint8 peerPub[32],
	uint8 out[148])
{
	memcpy(fOurPriv, ourPriv, 32);
	memcpy(fPeerStatic, peerPub, 32);

	uint8 staticPub[32];
	if (!wg::DhPublic(fOurPriv, staticPub))
		return -1;

	// C = Hash(CONSTRUCTION); H = Hash(Hash(C || IDENTIFIER) || Spub_r)
	wg::Hash(kConstruction, sizeof(kConstruction) - 1, fChainingKey);
	{
		wg::Blake2s s;
		wg::HashInit(s);
		wg::HashUpdate(s, fChainingKey, 32);
		wg::HashUpdate(s, kIdentifier, sizeof(kIdentifier) - 1);
		wg::HashFinal(s, fHash);
	}
	mix_hash(fHash, fPeerStatic, 32);

	// -> e
	if (!wg::DhGenerate(fEphemeralPriv, fEphemeralPub))
		return -1;
	wg::Kdf1(fChainingKey, fEphemeralPub, 32, fChainingKey);
	mix_hash(fHash, fEphemeralPub, 32);

	uint8 dh[32];
	uint8 key[32];

	// encrypted_static (es)
	if (!wg::Dh(fEphemeralPriv, fPeerStatic, dh))
		return -1;
	wg::Kdf2(fChainingKey, dh, 32, fChainingKey, key);
	uint8 encStatic[48];
	if (!wg::AeadEncrypt(key, 0, staticPub, 32, fHash, 32, encStatic))
		return -1;
	mix_hash(fHash, encStatic, 48);

	// encrypted_timestamp (ss)
	if (!wg::Dh(fOurPriv, fPeerStatic, dh))
		return -1;
	wg::Kdf2(fChainingKey, dh, 32, fChainingKey, key);
	uint8 timestamp[12];
	wg::Tai64n(timestamp);
	uint8 encTs[28];
	if (!wg::AeadEncrypt(key, 0, timestamp, 12, fHash, 32, encTs))
		return -1;
	mix_hash(fHash, encTs, 28);

	// Assemble the 148-byte type-1 message.
	if (!wg::RandomBytes(&fSenderIndex, sizeof(fSenderIndex)))
		return -1;
	memset(out, 0, 148);
	out[0] = 1;
	store32_le(out + 4, fSenderIndex);
	memcpy(out + 8, fEphemeralPub, 32);
	memcpy(out + 40, encStatic, 48);
	memcpy(out + 88, encTs, 28);
	// mac1 = MAC(Hash(LABEL_MAC1 || Spub_r), msg[0:116]); mac2 stays zero.
	uint8 mac1Key[32];
	{
		wg::Blake2s s;
		wg::HashInit(s);
		wg::HashUpdate(s, kLabelMac1, sizeof(kLabelMac1));
		wg::HashUpdate(s, fPeerStatic, 32);
		wg::HashFinal(s, mac1Key);
	}
	wg::Mac16(mac1Key, out, 116, out + 116);
	return 148;
}


bool
WGPeer::ConsumeResponse(const uint8* resp, size_t len)
{
	if (resp == NULL || len != 92 || resp[0] != 2)
		return false;
	if (load32_le(resp + 8) != fSenderIndex)
		return false;

	uint32 receiverIndex = load32_le(resp + 4);
	const uint8* peerEphemeral = resp + 12;
	const uint8* encNothing = resp + 44;	// 16 bytes: empty plaintext + tag

	uint8 dh[32];
	wg::Kdf1(fChainingKey, peerEphemeral, 32, fChainingKey);
	mix_hash(fHash, peerEphemeral, 32);
	if (!wg::Dh(fEphemeralPriv, peerEphemeral, dh))		// ee
		return false;
	wg::Kdf1(fChainingKey, dh, 32, fChainingKey);
	if (!wg::Dh(fOurPriv, peerEphemeral, dh))			// se
		return false;
	wg::Kdf1(fChainingKey, dh, 32, fChainingKey);

	// No preshared key for Tailscale peers.
	uint8 psk[32];
	memset(psk, 0, 32);
	uint8 tau[32];
	uint8 key[32];
	wg::Kdf3(fChainingKey, psk, 32, fChainingKey, tau, key);
	mix_hash(fHash, tau, 32);

	uint8 empty[1];
	if (!wg::AeadDecrypt(key, 0, encNothing, 16, fHash, 32, empty))
		return false;
	mix_hash(fHash, encNothing, 16);

	// Transport keys: initiator send/recv = KDF2(C, empty).
	uint8 sendKey[32];
	uint8 recvKey[32];
	wg::Kdf2(fChainingKey, NULL, 0, sendKey, recvKey);
	SetTransport(sendKey, recvKey, receiverIndex);
	return true;
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
