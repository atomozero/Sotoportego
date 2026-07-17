/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * BLAKE2s below is the public-domain reference implementation (CC0), adapted
 * to this file's style. X25519 and ChaCha20-Poly1305 wrap OpenSSL libcrypto.
 */
#include "WireGuardCrypto.h"

#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>


namespace {

// --- little-/big-endian helpers --------------------------------------------

inline uint32
load32_le(const uint8* p)
{
	return (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
}

inline void
store32_le(uint8* p, uint32 v)
{
	p[0] = (uint8)v; p[1] = (uint8)(v >> 8);
	p[2] = (uint8)(v >> 16); p[3] = (uint8)(v >> 24);
}

inline void
store64_le(uint8* p, uint64 v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (uint8)(v >> (8 * i));
}

inline uint32
rotr32(uint32 x, unsigned c)
{
	return (x >> c) | (x << (32 - c));
}


// --- BLAKE2s reference ------------------------------------------------------

const uint32 kIV[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

const uint8 kSigma[10][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

void
blake2s_increment(wg::Blake2s& s, uint32 inc)
{
	s.t[0] += inc;
	s.t[1] += (s.t[0] < inc) ? 1 : 0;
}

void
blake2s_compress(wg::Blake2s& s, const uint8 block[64])
{
	uint32 m[16];
	uint32 v[16];
	for (int i = 0; i < 16; i++)
		m[i] = load32_le(block + 4 * i);
	for (int i = 0; i < 8; i++)
		v[i] = s.h[i];
	for (int i = 0; i < 8; i++)
		v[8 + i] = kIV[i];
	v[12] ^= s.t[0];
	v[13] ^= s.t[1];
	v[14] ^= s.f[0];
	v[15] ^= s.f[1];

#define G(r, i, a, b, c, d) \
	a = a + b + m[kSigma[r][2 * i + 0]]; \
	d = rotr32(d ^ a, 16); \
	c = c + d; \
	b = rotr32(b ^ c, 12); \
	a = a + b + m[kSigma[r][2 * i + 1]]; \
	d = rotr32(d ^ a, 8); \
	c = c + d; \
	b = rotr32(b ^ c, 7);

	for (int r = 0; r < 10; r++) {
		G(r, 0, v[0], v[4], v[8], v[12]);
		G(r, 1, v[1], v[5], v[9], v[13]);
		G(r, 2, v[2], v[6], v[10], v[14]);
		G(r, 3, v[3], v[7], v[11], v[15]);
		G(r, 4, v[0], v[5], v[10], v[15]);
		G(r, 5, v[1], v[6], v[11], v[12]);
		G(r, 6, v[2], v[7], v[8], v[13]);
		G(r, 7, v[3], v[4], v[9], v[14]);
	}
#undef G

	for (int i = 0; i < 8; i++)
		s.h[i] ^= v[i] ^ v[8 + i];
}

// Full BLAKE2s init with an optional key and a chosen output length.
void
blake2s_init_key(wg::Blake2s& s, uint8 outLen, const uint8* key, uint8 keyLen)
{
	memset(&s, 0, sizeof(s));
	for (int i = 0; i < 8; i++)
		s.h[i] = kIV[i];
	// Parameter block: digest length, key length, fanout=1, depth=1.
	s.h[0] ^= 0x01010000UL ^ ((uint32)keyLen << 8) ^ (uint32)outLen;
	s.outlen = outLen;
	s.buflen = 0;

	if (keyLen > 0) {
		uint8 block[64];
		memset(block, 0, sizeof(block));
		memcpy(block, key, keyLen);
		wg::HashUpdate(s, block, 64);
	}
}

}	// namespace


// --- BLAKE2s public API ----------------------------------------------------

void
wg::HashInit(Blake2s& state)
{
	blake2s_init_key(state, 32, NULL, 0);
}


void
wg::HashUpdate(Blake2s& s, const void* in, size_t inLen)
{
	if (inLen == 0)
		return;
	const uint8* p = (const uint8*)in;

	size_t left = s.buflen;
	size_t fill = 64 - left;
	if (inLen > fill) {
		// The current buffer fills a full block; only compress it because we
		// know more input follows (the last block is deferred to Final).
		s.buflen = 0;
		memcpy(s.buf + left, p, fill);
		blake2s_increment(s, 64);
		blake2s_compress(s, s.buf);
		p += fill;
		inLen -= fill;
		while (inLen > 64) {
			blake2s_increment(s, 64);
			blake2s_compress(s, p);
			p += 64;
			inLen -= 64;
		}
	}
	memcpy(s.buf + s.buflen, p, inLen);
	s.buflen += inLen;
}


void
wg::HashFinal(Blake2s& s, uint8* out)
{
	blake2s_increment(s, (uint32)s.buflen);
	s.f[0] = 0xFFFFFFFFUL;		// last-block flag
	memset(s.buf + s.buflen, 0, 64 - s.buflen);
	blake2s_compress(s, s.buf);

	uint8 full[32];
	for (int i = 0; i < 8; i++)
		store32_le(full + 4 * i, s.h[i]);
	memcpy(out, full, s.outlen);
}


void
wg::Hash(const void* in, size_t inLen, uint8 out[32])
{
	Blake2s s;
	HashInit(s);
	HashUpdate(s, in, inLen);
	HashFinal(s, out);
}


void
wg::Mac16(const uint8 key[32], const void* in, size_t inLen, uint8 out[16])
{
	Blake2s s;
	blake2s_init_key(s, 16, key, 32);
	HashUpdate(s, in, inLen);
	HashFinal(s, out);
}


void
wg::Hmac(const uint8* key, size_t keyLen, const void* in, size_t inLen,
	uint8 out[32])
{
	uint8 block[64];
	uint8 ipad[64];
	uint8 opad[64];

	memset(block, 0, sizeof(block));
	if (keyLen > 64) {
		// Not reached for WireGuard (all keys are <= 32), but keep HMAC honest.
		Hash(key, keyLen, block);
	} else if (keyLen > 0) {
		memcpy(block, key, keyLen);
	}
	for (int i = 0; i < 64; i++) {
		ipad[i] = block[i] ^ 0x36;
		opad[i] = block[i] ^ 0x5C;
	}

	uint8 inner[32];
	Blake2s s;
	HashInit(s);
	HashUpdate(s, ipad, 64);
	HashUpdate(s, in, inLen);
	HashFinal(s, inner);

	HashInit(s);
	HashUpdate(s, opad, 64);
	HashUpdate(s, inner, 32);
	HashFinal(s, out);
}


// --- HKDF ------------------------------------------------------------------

void
wg::Kdf1(const uint8 ck[32], const void* input, size_t inLen, uint8 out1[32])
{
	uint8 tau0[32];
	Hmac(ck, 32, input, inLen, tau0);
	uint8 one = 0x01;
	Hmac(tau0, 32, &one, 1, out1);
}


void
wg::Kdf2(const uint8 ck[32], const void* input, size_t inLen,
	uint8 out1[32], uint8 out2[32])
{
	uint8 tau0[32];
	Hmac(ck, 32, input, inLen, tau0);
	uint8 one = 0x01;
	Hmac(tau0, 32, &one, 1, out1);
	uint8 buf[33];
	memcpy(buf, out1, 32);
	buf[32] = 0x02;
	Hmac(tau0, 32, buf, 33, out2);
}


void
wg::Kdf3(const uint8 ck[32], const void* input, size_t inLen,
	uint8 out1[32], uint8 out2[32], uint8 out3[32])
{
	uint8 tau0[32];
	Hmac(ck, 32, input, inLen, tau0);
	uint8 one = 0x01;
	Hmac(tau0, 32, &one, 1, out1);
	uint8 buf[33];
	memcpy(buf, out1, 32);
	buf[32] = 0x02;
	Hmac(tau0, 32, buf, 33, out2);
	memcpy(buf, out2, 32);
	buf[32] = 0x03;
	Hmac(tau0, 32, buf, 33, out3);
}


// --- X25519 (OpenSSL) ------------------------------------------------------

bool
wg::DhGenerate(uint8 priv[32], uint8 pub[32])
{
	EVP_PKEY* key = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	if (ctx == NULL)
		return false;
	bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1;
	if (ok) {
		size_t len = 32;
		ok = EVP_PKEY_get_raw_private_key(key, priv, &len) == 1 && len == 32;
		len = 32;
		ok = ok && EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == 32;
	}
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	return ok;
}


bool
wg::DhPublic(const uint8 priv[32], uint8 pub[32])
{
	EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
		priv, 32);
	if (key == NULL)
		return false;
	size_t len = 32;
	bool ok = EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == 32;
	EVP_PKEY_free(key);
	return ok;
}


bool
wg::Dh(const uint8 priv[32], const uint8 peerPub[32], uint8 shared[32])
{
	EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
		priv, 32);
	EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
		peerPub, 32);
	bool ok = false;
	if (key != NULL && peer != NULL) {
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
		if (ctx != NULL) {
			size_t len = 32;
			ok = EVP_PKEY_derive_init(ctx) == 1
				&& EVP_PKEY_derive_set_peer(ctx, peer) == 1
				&& EVP_PKEY_derive(ctx, shared, &len) == 1 && len == 32;
			EVP_PKEY_CTX_free(ctx);
		}
	}
	EVP_PKEY_free(key);
	EVP_PKEY_free(peer);
	return ok;
}


// --- ChaCha20-Poly1305 (OpenSSL) -------------------------------------------

bool
wg::AeadEncrypt(const uint8 key[32], uint64 counter,
	const void* plain, size_t plainLen, const void* aad, size_t aadLen,
	uint8* out)
{
	uint8 nonce[12];
	memset(nonce, 0, 4);
	store64_le(nonce + 4, counter);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return false;

	bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
			NULL) == 1
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1
		&& EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

	int len = 0;
	if (ok && aadLen > 0)
		ok = EVP_EncryptUpdate(ctx, NULL, &len, (const uint8*)aad,
			(int)aadLen) == 1;
	if (ok)
		ok = EVP_EncryptUpdate(ctx, out, &len, (const uint8*)plain,
			(int)plainLen) == 1;
	if (ok) {
		int fin = 0;
		ok = EVP_EncryptFinal_ex(ctx, out + len, &fin) == 1;
	}
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
			out + plainLen) == 1;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ok;
}


bool
wg::AeadDecrypt(const uint8 key[32], uint64 counter,
	const void* cipher, size_t cipherLen, const void* aad, size_t aadLen,
	uint8* out)
{
	if (cipherLen < 16)
		return false;
	size_t ctLen = cipherLen - 16;
	const uint8* ct = (const uint8*)cipher;
	uint8* tag = (uint8*)(ct + ctLen);

	uint8 nonce[12];
	memset(nonce, 0, 4);
	store64_le(nonce + 4, counter);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return false;

	bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
			NULL) == 1
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1
		&& EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

	int len = 0;
	if (ok && aadLen > 0)
		ok = EVP_DecryptUpdate(ctx, NULL, &len, (const uint8*)aad,
			(int)aadLen) == 1;
	if (ok)
		ok = EVP_DecryptUpdate(ctx, out, &len, ct, (int)ctLen) == 1;
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1;
		int fin = 0;
		// Final returns > 0 only when the tag verifies.
		ok = ok && EVP_DecryptFinal_ex(ctx, out + len, &fin) > 0;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ok;
}


// --- misc ------------------------------------------------------------------

bool
wg::RandomBytes(void* out, size_t len)
{
	return RAND_bytes((uint8*)out, (int)len) == 1;
}


void
wg::Tai64n(uint8 out[12])
{
	// TAI64N: 8-byte second label (2^62 + 10 leap seconds + unix seconds, big-
	// endian) followed by 4-byte nanoseconds (big-endian). On a first
	// handshake the responder accepts any value; it only enforces monotonic
	// increase for replay protection thereafter.
	uint64 seconds = 0x400000000000000AULL + (uint64)time(NULL);
	for (int i = 0; i < 8; i++)
		out[i] = (uint8)(seconds >> (8 * (7 - i)));
	// Nanoseconds left at zero -- we don't have sub-second precision here and
	// don't need it for acceptance.
	out[8] = out[9] = out[10] = out[11] = 0;
}
