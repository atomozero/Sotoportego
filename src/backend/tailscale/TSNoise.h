/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_NOISE_H
#define TS_NOISE_H


#include <stddef.h>
#include <sys/types.h>

#include <SupportDefs.h>


// Noise IK handshake for the Tailscale control channel ("ts2021").
//
// Tailscale's control protocol runs a Noise IK handshake with the exact suite
// WireGuard uses -- Curve25519 / ChaCha20-Poly1305 / BLAKE2s -- so this reuses
// the primitives already validated in WireGuardCrypto (X25519 DH, the ChaCha
// AEAD whose 12-byte nonce is `0x00000000 || counter_le64`, exactly Noise's
// nonce, and BLAKE2s for the HKDF/hash mixing) rather than adding a dependency.
// What is new here is only the generic Noise state machine -- SymmetricState +
// HandshakeState for the IK pattern -- which WireGuardCrypto does not expose
// (its handshake assembly is WireGuard-message-specific).
//
// Full Noise protocol name: "Noise_IK_25519_ChaChaPoly_BLAKE2s".
//
// IK message pattern (initiator drives; responder is the control server):
//     <- s                (pre-message: initiator already knows responder static)
//     -> e, es, s, ss     (message 1: NoiseIK::WriteMessage1 / ReadMessage1)
//     <- e, ee, se        (message 2: NoiseIK::WriteMessage2 / ReadMessage2)
//
// After the two messages, Split() derives the two directional transport keys.
// The ts2021 framing on top (message-type/version headers, HTTP transport) is a
// separate layer; this class is transport-agnostic and operates on byte buffers,
// which is what lets it be unit-tested by handshaking an initiator against a
// responder entirely in-process.
namespace ts {

// Wire sizes produced by the IK messages, so callers can size buffers.
//   msg1 = e(32) + enc_static(32+16) + enc_payload(len+16)
//   msg2 = e(32) + enc_payload(len+16)
static const size_t kNoiseDHLen		= 32;
static const size_t kNoiseTagLen	= 16;
static const size_t kNoiseMsg1Overhead = 32 + (32 + 16) + 16;	// 96, payload=0
static const size_t kNoiseMsg2Overhead = 32 + 16;				// 48, payload=0


// The two directional transport keys produced by Split(), from the initiator's
// point of view. Each direction's nonce counter starts at 0.
struct NoiseTransportKeys {
	uint8	sendKey[32];	// initiator -> responder
	uint8	recvKey[32];	// responder -> initiator
};


class NoiseIK {
public:
								NoiseIK();

			// Initiator setup: our long-term static keypair plus the responder's
			// known static public key (fetched out-of-band from the control
			// server's /key endpoint). Optional prologue is mixed in per Noise.
			void				InitInitiator(const uint8 staticPriv[32],
									const uint8 staticPub[32],
									const uint8 remoteStaticPub[32],
									const void* prologue, size_t prologueLen);

			// Responder setup (used for the in-process self-test and, later, a
			// mock control server): our static keypair; the peer's static is
			// learned from message 1.
			void				InitResponder(const uint8 staticPriv[32],
									const uint8 staticPub[32],
									const void* prologue, size_t prologueLen);

			// Initiator: write handshake message 1 (-> e, es, s, ss) carrying an
			// optional payload. Returns bytes written, or -1 on error/overflow.
			ssize_t				WriteMessage1(const void* payload,
									size_t payloadLen, uint8* out, size_t outCap);
			// Responder: consume message 1, recovering the payload. Returns
			// payload length, or -1 on decrypt/format failure.
			ssize_t				ReadMessage1(const uint8* in, size_t inLen,
									uint8* payloadOut, size_t payloadCap);

			// Responder: write handshake message 2 (<- e, ee, se).
			ssize_t				WriteMessage2(const void* payload,
									size_t payloadLen, uint8* out, size_t outCap);
			// Initiator: consume message 2, recovering the payload.
			ssize_t				ReadMessage2(const uint8* in, size_t inLen,
									uint8* payloadOut, size_t payloadCap);

			// Derive the transport keys. Fills `keys` from the initiator's
			// perspective regardless of which side calls it, so a caller on the
			// responder side swaps send/recv itself. Valid only after the
			// handshake messages this side participates in have completed.
			bool				Split(NoiseTransportKeys& keys) const;

			// The peer static public key the responder learned from message 1
			// (32 bytes). Meaningful on the responder after ReadMessage1.
			const uint8*		RemoteStatic() const { return fRemoteStatic; }
			// The final handshake hash `h` (channel binding). Valid after the
			// handshake completes.
			const uint8*		HandshakeHash() const { return fH; }

private:
			// --- SymmetricState ---
			void				_InitSymmetric(const void* prologue,
									size_t prologueLen);
			void				_MixHash(const void* data, size_t len);
			void				_MixKey(const uint8 input[32]);
			// EncryptAndHash: writes len (+16 if keyed) bytes to out, returns
			// that count. DecryptAndHash: returns plaintext length or -1.
			size_t				_EncryptAndHash(const void* plain, size_t len,
									uint8* out);
			ssize_t				_DecryptAndHash(const uint8* cipher, size_t len,
									uint8* out);

			uint8				fCK[32];		// chaining key
			uint8				fH[32];			// handshake hash
			uint8				fK[32];			// current AEAD key
			bool				fHasKey;
			uint64				fN;				// AEAD nonce counter

			// HandshakeState material.
			uint8				fStaticPriv[32];
			uint8				fStaticPub[32];
			uint8				fEphemeralPriv[32];
			uint8				fEphemeralPub[32];
			uint8				fRemoteStatic[32];
			uint8				fRemoteEphemeral[32];
			bool				fInitiator;
};

}	// namespace ts


#endif	// TS_NOISE_H
