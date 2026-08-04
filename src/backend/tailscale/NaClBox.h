/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef NACL_BOX_H
#define NACL_BOX_H


#include <stddef.h>

#include <SupportDefs.h>


// NaCl "box" authenticated public-key encryption -- Curve25519 key agreement
// plus XSalsa20-Poly1305 -- as used by Tailscale's `disco` endpoint-probing
// protocol. This is the one cryptographic primitive the WireGuard/Noise reuse
// couldn't cover (XSalsa20 and Poly1305 aren't exposed by OpenSSL), so the
// Salsa20 core, HSalsa20, XSalsa20 stream and Poly1305 MAC are bundled here from
// the public-domain TweetNaCl reference; the Curve25519 scalar multiplication
// reuses OpenSSL's X25519 (wg::Dh), which is identical to NaCl's crypto_scalarmult.
//
// All functions are validated against the canonical NaCl box test vectors in the
// host-side test.
namespace ts {

// Derive the shared box key from a peer public key and our secret key
// (crypto_box_beforenm: X25519 then HSalsa20). Writes 32 bytes. Returns false
// only if the scalar multiplication fails.
bool	BoxBeforeNm(uint8 key[32], const uint8 peerPublic[32],
			const uint8 secret[32]);

// Seal `mlen` plaintext bytes under a precomputed box key and 24-byte nonce.
// `out` receives mlen + 16 bytes (the 16-byte Poly1305 tag followed by the
// ciphertext). Returns false on allocation failure.
bool	BoxSealWithKey(uint8* out, const uint8* msg, size_t mlen,
			const uint8 nonce[24], const uint8 key[32]);

// Open a sealed message (clen = mlen + 16) under a precomputed box key. `out`
// receives clen - 16 plaintext bytes. Returns false if authentication fails.
bool	BoxOpenWithKey(uint8* out, const uint8* cipher, size_t clen,
			const uint8 nonce[24], const uint8 key[32]);

// Convenience one-shots that derive the shared key from peerPublic + secret.
bool	BoxSeal(uint8* out, const uint8* msg, size_t mlen,
			const uint8 nonce[24], const uint8 peerPublic[32],
			const uint8 secret[32]);
bool	BoxOpen(uint8* out, const uint8* cipher, size_t clen,
			const uint8 nonce[24], const uint8 peerPublic[32],
			const uint8 secret[32]);

}	// namespace ts


#endif	// NACL_BOX_H
