/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WIREGUARD_CRYPTO_H
#define WIREGUARD_CRYPTO_H


#include <stddef.h>

#include <SupportDefs.h>


// Cryptographic primitives for WireGuard's Noise_IKpsk2 handshake.
//
// WireGuard fixes the suite to Curve25519 / ChaCha20-Poly1305 / BLAKE2s.
// BLAKE2s (the 32-bit variant, keyed and with variable output length) is not
// exposed by either libsodium or OpenSSL's EVP layer, so it is bundled here as
// the public-domain reference implementation. X25519 and ChaCha20-Poly1305 come
// from OpenSSL's libcrypto (already on the system for openvpn).
//
// Every primitive is validated against its RFC test vector in the host-side
// test; the handshake assembly on top still needs validation against a real
// WireGuard peer.
namespace wg {

// --- BLAKE2s ---------------------------------------------------------------

// Streaming state for the unkeyed 32-byte hash used all over the handshake
// (H = Hash(H || x) style mixing). Exposed so callers can absorb several
// chunks without concatenating buffers.
struct Blake2s {
	uint32	h[8];
	uint32	t[2];
	uint32	f[2];
	uint8	buf[64];
	size_t	buflen;
	uint8	outlen;
};

void	HashInit(Blake2s& state);
void	HashUpdate(Blake2s& state, const void* in, size_t inLen);
void	HashFinal(Blake2s& state, uint8* out);		// writes 32 bytes
void	Hash(const void* in, size_t inLen, uint8 out[32]);

// Keyed BLAKE2s with a 16-byte digest -- WireGuard's MAC() for mac1/mac2.
void	Mac16(const uint8 key[32], const void* in, size_t inLen, uint8 out[16]);

// HMAC-BLAKE2s (32-byte). Used to build the HKDF below.
void	Hmac(const uint8* key, size_t keyLen, const void* in, size_t inLen,
			uint8 out[32]);

// WireGuard's HKDF: KDFn(key, input) -> first n of the HMAC chain.
void	Kdf1(const uint8 ck[32], const void* input, size_t inLen,
			uint8 out1[32]);
void	Kdf2(const uint8 ck[32], const void* input, size_t inLen,
			uint8 out1[32], uint8 out2[32]);
void	Kdf3(const uint8 ck[32], const void* input, size_t inLen,
			uint8 out1[32], uint8 out2[32], uint8 out3[32]);

// --- X25519 (OpenSSL) ------------------------------------------------------

bool	DhGenerate(uint8 priv[32], uint8 pub[32]);	// fresh ephemeral keypair
bool	DhPublic(const uint8 priv[32], uint8 pub[32]);	// public from private
bool	Dh(const uint8 priv[32], const uint8 peerPub[32], uint8 shared[32]);

// --- ChaCha20-Poly1305 (OpenSSL) -------------------------------------------
// 12-byte nonce = 4 zero bytes || `counter` as 64-bit little-endian, matching
// WireGuard. `out` for encrypt is plainLen + 16 (tag appended); for decrypt
// `cipherLen` includes the 16-byte tag and `out` is cipherLen - 16.

bool	AeadEncrypt(const uint8 key[32], uint64 counter,
			const void* plain, size_t plainLen,
			const void* aad, size_t aadLen, uint8* out);
bool	AeadDecrypt(const uint8 key[32], uint64 counter,
			const void* cipher, size_t cipherLen,
			const void* aad, size_t aadLen, uint8* out);

// --- misc ------------------------------------------------------------------

bool	RandomBytes(void* out, size_t len);
void	Tai64n(uint8 out[12]);		// current time as a 12-byte TAI64N label

}	// namespace wg


#endif	// WIREGUARD_CRYPTO_H
