/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * The Salsa20 core, XSalsa20 stream and Poly1305 MAC below are ported from the
 * public-domain TweetNaCl reference (D. J. Bernstein et al.); the Curve25519
 * scalar multiplication delegates to OpenSSL's X25519 via wg::Dh.
 */
#include "NaClBox.h"

#include <stdlib.h>
#include <string.h>

#include "WireGuardCrypto.h"


namespace ts {

typedef uint8 u8;
typedef uint32 u32;
typedef uint64 u64;

static const u8 kSigma[16] = { 'e','x','p','a','n','d',' ','3','2','-','b','y',
	't','e',' ','k' };


static u32
L32(u32 x, int c)
{
	return (x << c) | ((x & 0xffffffff) >> (32 - c));
}


static u32
ld32(const u8* x)
{
	u32 u = x[3];
	u = (u << 8) | x[2];
	u = (u << 8) | x[1];
	return (u << 8) | x[0];
}


static void
st32(u8* x, u32 u)
{
	for (int i = 0; i < 4; i++) {
		x[i] = (u8)u;
		u >>= 8;
	}
}


static int
vn(const u8* x, const u8* y, int n)
{
	u32 d = 0;
	for (int i = 0; i < n; i++)
		d |= x[i] ^ y[i];
	return (1 & ((d - 1) >> 8)) - 1;
}


static void
core(u8* out, const u8* in, const u8* k, const u8* c, int h)
{
	u32 w[16], x[16], y[16], t[4];
	int i, j, m;

	for (i = 0; i < 4; i++) {
		x[5 * i] = ld32(c + 4 * i);
		x[1 + i] = ld32(k + 4 * i);
		x[6 + i] = ld32(in + 4 * i);
		x[11 + i] = ld32(k + 16 + 4 * i);
	}
	for (i = 0; i < 16; i++)
		y[i] = x[i];

	for (i = 0; i < 20; i++) {
		for (j = 0; j < 4; j++) {
			for (m = 0; m < 4; m++)
				t[m] = x[(5 * j + 4 * m) % 16];
			t[1] ^= L32(t[0] + t[3], 7);
			t[2] ^= L32(t[1] + t[0], 9);
			t[3] ^= L32(t[2] + t[1], 13);
			t[0] ^= L32(t[3] + t[2], 18);
			for (m = 0; m < 4; m++)
				w[4 * j + (j + m) % 4] = t[m];
		}
		for (m = 0; m < 16; m++)
			x[m] = w[m];
	}

	if (h) {
		for (i = 0; i < 16; i++)
			x[i] += y[i];
		for (i = 0; i < 4; i++) {
			x[5 * i] -= ld32(c + 4 * i);
			x[6 + i] -= ld32(in + 4 * i);
		}
		for (i = 0; i < 4; i++) {
			st32(out + 4 * i, x[5 * i]);
			st32(out + 16 + 4 * i, x[6 + i]);
		}
	} else {
		for (i = 0; i < 16; i++)
			st32(out + 4 * i, x[i] + y[i]);
	}
}


static void
salsa20(u8* out, const u8* in, const u8* k, const u8* c)
{
	core(out, in, k, c, 0);
}


static void
hsalsa20(u8* out, const u8* in, const u8* k, const u8* c)
{
	core(out, in, k, c, 1);
}


static void
stream_salsa20_xor(u8* c, const u8* m, u64 b, const u8* n, const u8* k)
{
	u8 z[16], x[64];
	u32 u;
	u64 i;
	if (b == 0)
		return;
	for (i = 0; i < 16; i++)
		z[i] = 0;
	for (i = 0; i < 8; i++)
		z[i] = n[i];
	while (b >= 64) {
		salsa20(x, z, k, kSigma);
		for (i = 0; i < 64; i++)
			c[i] = (m ? m[i] : 0) ^ x[i];
		u = 1;
		for (i = 8; i < 16; i++) {
			u += (u32)z[i];
			z[i] = (u8)u;
			u >>= 8;
		}
		b -= 64;
		c += 64;
		if (m)
			m += 64;
	}
	if (b) {
		salsa20(x, z, k, kSigma);
		for (i = 0; i < b; i++)
			c[i] = (m ? m[i] : 0) ^ x[i];
	}
}


static void
stream_xsalsa20_xor(u8* c, const u8* m, u64 d, const u8* n, const u8* k)
{
	u8 s[32];
	hsalsa20(s, n, k, kSigma);
	stream_salsa20_xor(c, m, d, n + 16, s);
}


// --- Poly1305 --------------------------------------------------------------

static const u32 kMinusP[17] = {
	5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
};

static void
add1305(u32* h, const u32* c)
{
	u32 u = 0;
	for (u32 j = 0; j < 17; j++) {
		u += h[j] + c[j];
		h[j] = u & 255;
		u >>= 8;
	}
}


static void
onetimeauth(u8* out, const u8* m, u64 n, const u8* k)
{
	u32 s, i, j, u, x[17], r[17], h[17], c[17], g[17];

	for (j = 0; j < 17; j++)
		r[j] = h[j] = 0;
	for (j = 0; j < 16; j++)
		r[j] = k[j];
	r[3] &= 15; r[4] &= 252; r[7] &= 15; r[8] &= 252;
	r[11] &= 15; r[12] &= 252; r[15] &= 15;

	while (n > 0) {
		for (j = 0; j < 17; j++)
			c[j] = 0;
		for (j = 0; (j < 16) && (j < n); j++)
			c[j] = m[j];
		c[j] = 1;
		m += j;
		n -= j;
		add1305(h, c);
		for (i = 0; i < 17; i++) {
			x[i] = 0;
			for (j = 0; j < 17; j++)
				x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
		}
		for (i = 0; i < 17; i++)
			h[i] = x[i];
		u = 0;
		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u & 3;
		u = 5 * (u >> 2);
		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u;
	}

	for (j = 0; j < 17; j++)
		g[j] = h[j];
	add1305(h, kMinusP);
	s = (u32)(-(h[16] >> 7));
	for (j = 0; j < 17; j++)
		h[j] ^= s & (g[j] ^ h[j]);

	for (j = 0; j < 16; j++)
		c[j] = k[j + 16];
	c[16] = 0;
	add1305(h, c);
	for (j = 0; j < 16; j++)
		out[j] = (u8)h[j];
}


static int
onetimeauth_verify(const u8* h, const u8* m, u64 n, const u8* k)
{
	u8 x[16];
	onetimeauth(x, m, n, k);
	return vn(h, x, 16);
}


// --- secretbox (operates in the TweetNaCl zero-byte convention) ------------

static int
secretbox(u8* c, const u8* m, u64 d, const u8* n, const u8* k)
{
	if (d < 32)
		return -1;
	stream_xsalsa20_xor(c, m, d, n, k);
	onetimeauth(c + 16, c + 32, d - 32, c);
	for (int i = 0; i < 16; i++)
		c[i] = 0;
	return 0;
}


static int
secretbox_open(u8* m, const u8* c, u64 d, const u8* n, const u8* k)
{
	u8 x[32];
	if (d < 32)
		return -1;
	stream_xsalsa20_xor(x, NULL, 32, n, k);	// first 32 keystream bytes
	if (onetimeauth_verify(c + 16, c + 32, d - 32, x) != 0)
		return -1;
	stream_xsalsa20_xor(m, c, d, n, k);
	for (int i = 0; i < 32; i++)
		m[i] = 0;
	return 0;
}


// --- public API ------------------------------------------------------------

bool
BoxBeforeNm(uint8 key[32], const uint8 peerPublic[32], const uint8 secret[32])
{
	u8 s[32];
	if (!wg::Dh(secret, peerPublic, s))
		return false;
	static const u8 zero16[16] = { 0 };
	hsalsa20(key, zero16, s, kSigma);
	return true;
}


bool
BoxSealWithKey(uint8* out, const uint8* msg, size_t mlen, const uint8 nonce[24],
	const uint8 key[32])
{
	u64 d = (u64)mlen + 32;
	u8* m2 = (u8*)malloc(d);
	u8* c2 = (u8*)malloc(d);
	if (m2 == NULL || c2 == NULL) {
		free(m2);
		free(c2);
		return false;
	}
	memset(m2, 0, 32);
	if (mlen > 0)
		memcpy(m2 + 32, msg, mlen);
	secretbox(c2, m2, d, nonce, key);
	// c2[16..d-1] is tag(16) || ciphertext(mlen).
	memcpy(out, c2 + 16, mlen + 16);
	free(m2);
	free(c2);
	return true;
}


bool
BoxOpenWithKey(uint8* out, const uint8* cipher, size_t clen,
	const uint8 nonce[24], const uint8 key[32])
{
	if (clen < 16)
		return false;
	size_t mlen = clen - 16;
	u64 d = (u64)clen + 16;	// = mlen + 32
	u8* c2 = (u8*)malloc(d);
	u8* m2 = (u8*)malloc(d);
	if (c2 == NULL || m2 == NULL) {
		free(c2);
		free(m2);
		return false;
	}
	memset(c2, 0, 16);
	memcpy(c2 + 16, cipher, clen);
	int r = secretbox_open(m2, c2, d, nonce, key);
	if (r == 0 && mlen > 0)
		memcpy(out, m2 + 32, mlen);
	free(c2);
	free(m2);
	return r == 0;
}


bool
BoxSeal(uint8* out, const uint8* msg, size_t mlen, const uint8 nonce[24],
	const uint8 peerPublic[32], const uint8 secret[32])
{
	u8 key[32];
	if (!BoxBeforeNm(key, peerPublic, secret))
		return false;
	return BoxSealWithKey(out, msg, mlen, nonce, key);
}


bool
BoxOpen(uint8* out, const uint8* cipher, size_t clen, const uint8 nonce[24],
	const uint8 peerPublic[32], const uint8 secret[32])
{
	u8 key[32];
	if (!BoxBeforeNm(key, peerPublic, secret))
		return false;
	return BoxOpenWithKey(out, cipher, clen, nonce, key);
}

}	// namespace ts
