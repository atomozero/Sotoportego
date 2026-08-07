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

			// Cumulative application payload moved over this session, for the
			// live traffic view (excludes headers/padding/keepalives).
			uint64				TxBytes() const { return fTxBytes; }
			uint64				RxBytes() const { return fRxBytes; }

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

			// --- WireGuard Noise IKpsk2 handshake (responder) ---------------
			// A tailnet peer may itself initiate a (re)handshake: recover the
			// initiator's node public key from a 148-byte type-1 message, using our
			// node private key, WITHOUT touching any peer state -- so the caller can
			// route the initiation to the right peer before completing it. False if
			// the message doesn't decrypt/authenticate.
	static	bool				RecoverInitiatorStatic(const uint8 ourPriv[32],
									const uint8* msg, size_t len,
									uint8 outStatic[32]);
			// Consume a 148-byte type-1 initiation as the responder (our node
			// private key decrypts it); stash the responder handshake state. The
			// recovered initiator static must match this peer's node key. Returns
			// true on a valid, authenticated initiation.
			bool				ConsumeInitiation(const uint8 ourPriv[32],
									const uint8* msg, size_t len);
			// Complete the responder handshake begun by ConsumeInitiation: derive
			// and install the (direction-swapped) transport keys and build the
			// 92-byte type-2 response to `out`. Returns 92, or -1 on error.
			ssize_t				BuildResponse(uint8 out[92]);

			// --- session lifetime / rekey (WireGuard timers) ----------------
			// True once the live session has aged past REKEY_AFTER_TIME and we're
			// not already mid-retransmit: the caller should send a fresh initiation
			// (make-before-break -- the current keys stay usable until the response
			// installs new ones).
			bool				ShouldInitiateRekey(bigtime_t now) const;
			// True once nothing has been sent for the persistent-keepalive window:
			// the caller should send an empty transport packet to keep the session
			// (and any NAT mapping) warm.
			bool				ShouldKeepalive(bigtime_t now) const;
			// Drop the transport keys if the session has aged past
			// REJECT_AFTER_TIME (a rekey response never arrived); the next outbound
			// packet then starts a fresh handshake. Returns true if it expired.
			bool				ExpireIfStale(bigtime_t now);
			// Age of the live session in seconds, or -1 if no keys (for logging).
			int					SessionAgeSeconds(bigtime_t now) const;

			// Testing hook: pin the clock used for the internal lifetime stamps
			// (fEstablished / fLastInitiation / fLastSend) so a bench test can
			// drive session aging deterministically without waiting on real time.
			// A value of 0 (the default) means "use the real system clock". Not
			// used in production.
			void				SetTestClock(bigtime_t now) { fTestClock = now; }

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
			// The clock used for lifetime stamping: the injected test clock if set,
			// otherwise the real system clock.
			bigtime_t			_Now() const;
			// Shared responder decrypt (through the timestamp) used by both
			// RecoverInitiatorStatic and ConsumeInitiation: recompute the chaining
			// key/hash, decrypt the initiator static and verify the timestamp.
	static	bool				_ResponderConsume(const uint8 ourPriv[32],
									const uint8* msg, size_t len, uint8 outCk[32],
									uint8 outHash[32], uint8 outPeerEph[32],
									uint8 outStatic[32], uint32* outRecvIndex);

			uint8				fNodeKey[32];
			uint8				fSendKey[32];
			uint8				fRecvKey[32];
			bool				fHasKeys;
			uint32				fReceiverIndex;
			uint64				fSendCounter;

			uint64				fReplayCounter;
			uint64				fReplayBitmap[128];

			// Handshake state (between BuildInitiation and ConsumeResponse, or
			// ConsumeInitiation and BuildResponse).
			uint8				fOurPriv[32];
			uint8				fPeerStatic[32];
			uint8				fEphemeralPriv[32];
			uint8				fEphemeralPub[32];
			uint8				fPeerEphemeral[32];	// responder: initiator's e
			uint8				fChainingKey[32];
			uint8				fHash[32];
			uint32				fSenderIndex;
			uint32				fPendingReceiverIndex;	// responder: initiator's idx

			// Session lifetime timestamps (system_time), for rekey + keepalive.
			bigtime_t			fEstablished;		// when current keys installed
			bigtime_t			fLastInitiation;	// last initiation we sent
			bigtime_t			fLastSend;			// last transport packet sent
			bigtime_t			fTestClock;			// 0 = real clock (test hook)
			uint64				fTxBytes;			// app payload sent
			uint64				fRxBytes;			// app payload received
};

}	// namespace ts


#endif	// WG_PEER_H
