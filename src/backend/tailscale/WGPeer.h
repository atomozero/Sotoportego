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
};

}	// namespace ts


#endif	// WG_PEER_H
