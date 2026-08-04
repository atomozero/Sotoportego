/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WG_PEER_H
#define WG_PEER_H


#include <stddef.h>
#include <sys/types.h>

#include <SupportDefs.h>


// One WireGuard peer's data-plane transport state, factored out of
// WireGuardBackend so the Tailscale backend can run N peers keyed by node public
// key (a tailnet has many peers; the WireGuard backend has exactly one). It owns
// the per-direction transport keys, the send counter, the peer's receiver index
// and an RFC 6479 anti-replay window, and turns plaintext IP packets into
// WireGuard type-4 transport messages and back -- the same wire format
// WireGuardBackend uses, reusing WireGuardCrypto's ChaCha20-Poly1305.
//
// The Noise IKpsk2 handshake that produces the transport keys is per-peer too;
// this unit is fed the derived keys (SetTransport) once a handshake completes.
// The send path (a direct UDP sockaddr or via DERP) is chosen by magicsock and
// is not part of this unit -- it only frames/deframes packets.
namespace ts {

class WGPeer {
public:
								WGPeer();

			// Record the peer's node public key (used to route packets to/from
			// this peer in magicsock and DERP).
			void				SetNodeKey(const uint8 nodeKey[32]);
			const uint8*		NodeKey() const { return fNodeKey; }

			// Install the transport keys + the peer's receiver index once a
			// handshake completes; resets counters and the replay window.
			void				SetTransport(const uint8 sendKey[32],
									const uint8 recvKey[32], uint32 receiverIndex);
			bool				HasKeys() const { return fHasKeys; }

			// --- WireGuard Noise IKpsk2 handshake (initiator) ---------------
			// Build the 148-byte type-1 handshake initiation to `out`, using our
			// node private key and the peer's node public key; stashes the
			// ephemeral + chaining/hash state for ConsumeResponse. Tailscale
			// peers use no preshared key. Returns 148, or -1 on error.
			ssize_t				BuildInitiation(const uint8 ourPriv[32],
									const uint8 peerPub[32], uint8 out[148]);
			// Consume the 92-byte type-2 handshake response: derive the
			// transport keys and install them (SetTransport). Returns true on a
			// valid, authenticated response for our initiation.
			bool				ConsumeResponse(const uint8* resp, size_t len);
			// Our session index sent in the initiation (peers echo it back).
			uint32				SenderIndex() const { return fSenderIndex; }

			// Encapsulate a plaintext IP packet (plainLen 0 == keepalive) into a
			// type-4 transport message. `out` needs 16 + roundup16(plainLen) + 16
			// bytes. Returns the total length, or 0 on error.
			size_t				Encapsulate(const uint8* plain, size_t plainLen,
									uint8* out);

			// Decapsulate a received type-4 message into `out` (needs packetLen
			// bytes). Returns the plaintext IP-packet length (0 for a keepalive)
			// or -1 if it isn't valid or is a replay.
			ssize_t				Decapsulate(const uint8* packet,
									size_t packetLen, uint8* out);

			void				ResetReplay();

private:
			bool				_ReplayValidate(uint64 counter);

			uint8				fNodeKey[32];
			uint8				fSendKey[32];
			uint8				fRecvKey[32];
			bool				fHasKeys;
			uint32				fReceiverIndex;
			uint64				fSendCounter;

			uint64				fReplayCounter;
			uint64				fReplayBitmap[128];

			// Handshake state (between BuildInitiation and ConsumeResponse).
			uint8				fOurPriv[32];
			uint8				fPeerStatic[32];
			uint8				fEphemeralPriv[32];
			uint8				fEphemeralPub[32];
			uint8				fChainingKey[32];
			uint8				fHash[32];
			uint32				fSenderIndex;
};

}	// namespace ts


#endif	// WG_PEER_H
