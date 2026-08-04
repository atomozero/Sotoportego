/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSControlConn.h"

#include <string.h>

#include <openssl/evp.h>

#include "TSControl.h"		// CONTROL_MSG_RECORD, kRecordHeaderLen
#include "TSTls.h"


namespace ts {

static const size_t kTagLen				= 16;
static const size_t kMaxPlaintextPerRecord = 4077;	// maxMessageSize(4096)-3-16


// Build the 12-byte transport nonce: 4 zero bytes then the counter as a
// big-endian uint64. This is Tailscale's controlbase transport nonce, which --
// unlike the Noise handshake nonce -- is big-endian.
static void
build_nonce(uint64 counter, uint8 nonce[12])
{
	memset(nonce, 0, 4);
	for (int i = 0; i < 8; i++)
		nonce[4 + i] = (uint8)(counter >> (8 * (7 - i)));
}


// ChaCha20-Poly1305 seal with no AAD. `out` receives plaintextLen + 16 bytes
// (tag appended). Returns true on success.
static bool
aead_seal(const uint8 key[32], uint64 counter, const uint8* plain,
	size_t plainLen, uint8* out)
{
	uint8 nonce[12];
	build_nonce(counter, nonce);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return false;

	bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)
			== 1
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1
		&& EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

	int outLen = 0;
	if (ok) {
		ok = EVP_EncryptUpdate(ctx, out, &outLen, plain, (int)plainLen) == 1;
	}
	int finalLen = 0;
	if (ok)
		ok = EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen) == 1;
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)kTagLen,
			out + plainLen) == 1;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ok;
}


// ChaCha20-Poly1305 open with no AAD. `cipherLen` includes the 16-byte tag;
// `out` receives cipherLen - 16 plaintext bytes. Returns true if the tag
// verifies.
static bool
aead_open(const uint8 key[32], uint64 counter, const uint8* cipher,
	size_t cipherLen, uint8* out)
{
	if (cipherLen < kTagLen)
		return false;
	size_t plainLen = cipherLen - kTagLen;

	uint8 nonce[12];
	build_nonce(counter, nonce);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return false;

	bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)
			== 1
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1
		&& EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

	int outLen = 0;
	if (ok)
		ok = EVP_DecryptUpdate(ctx, out, &outLen, cipher, (int)plainLen) == 1;
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)kTagLen,
			(void*)(cipher + plainLen)) == 1;
	}
	int finalLen = 0;
	if (ok)
		ok = EVP_DecryptFinal_ex(ctx, out + outLen, &finalLen) == 1;

	EVP_CIPHER_CTX_free(ctx);
	return ok;
}


ControlConn::ControlConn()
	:
	fTls(NULL),
	fTxCounter(0),
	fRxCounter(0),
	fPendingLen(0),
	fPendingOff(0)
{
	memset(fTxKey, 0, sizeof(fTxKey));
	memset(fRxKey, 0, sizeof(fRxKey));
}


void
ControlConn::Init(TlsClient* tls, const NoiseTransportKeys& keys,
	const uint8* pending, size_t pendingLen)
{
	fTls = tls;
	memcpy(fTxKey, keys.sendKey, 32);
	memcpy(fRxKey, keys.recvKey, 32);
	fTxCounter = 0;
	fRxCounter = 0;

	fPendingLen = 0;
	fPendingOff = 0;
	if (pending != NULL && pendingLen > 0 && pendingLen <= sizeof(fPending)) {
		memcpy(fPending, pending, pendingLen);
		fPendingLen = pendingLen;
	}
}


status_t
ControlConn::WriteMessage(const void* data, size_t len)
{
	if (fTls == NULL)
		return B_NO_INIT;

	const uint8* p = (const uint8*)data;
	size_t remaining = len;
	// A zero-length message still needs no record; callers send >=1 byte.
	do {
		size_t chunk = remaining < kMaxPlaintextPerRecord
			? remaining : kMaxPlaintextPerRecord;

		uint8 frame[kRecordHeaderLen + kMaxPlaintextPerRecord + kTagLen];
		size_t cipherLen = chunk + kTagLen;
		frame[0] = (uint8)CONTROL_MSG_RECORD;
		frame[1] = (uint8)(cipherLen >> 8);
		frame[2] = (uint8)(cipherLen & 0xff);

		if (!aead_seal(fTxKey, fTxCounter, p, chunk,
				frame + kRecordHeaderLen)) {
			return B_ERROR;
		}
		fTxCounter++;

		size_t frameLen = kRecordHeaderLen + cipherLen;
		size_t written = 0;
		while (written < frameLen) {
			ssize_t n = fTls->Write(frame + written, frameLen - written);
			if (n <= 0)
				return B_IO_ERROR;
			written += (size_t)n;
		}

		p += chunk;
		remaining -= chunk;
	} while (remaining > 0);

	return B_OK;
}


ssize_t
ControlConn::ReadRecord(uint8* buf, size_t cap)
{
	if (fTls == NULL)
		return -1;

	uint8 header[kRecordHeaderLen];
	status_t result = _ReadFull(header, kRecordHeaderLen);
	if (result == B_ENTRY_NOT_FOUND)
		return 0;	// clean EOF at a record boundary
	if (result == B_WOULD_BLOCK)
		return -2;	// receive timeout at a record boundary -- caller may retry
	if (result != B_OK)
		return -1;

	uint8 type = header[0];
	size_t cipherLen = ((size_t)header[1] << 8) | (size_t)header[2];
	if (type != CONTROL_MSG_RECORD || cipherLen < kTagLen)
		return -1;
	if (cipherLen - kTagLen > cap)
		return -1;

	uint8 cipher[kMaxPlaintextPerRecord + kTagLen];
	if (cipherLen > sizeof(cipher))
		return -1;
	if (_ReadFull(cipher, cipherLen) != B_OK)
		return -1;

	if (!aead_open(fRxKey, fRxCounter, cipher, cipherLen, buf))
		return -1;
	fRxCounter++;

	return (ssize_t)(cipherLen - kTagLen);
}


status_t
ControlConn::_ReadFull(uint8* buf, size_t len)
{
	size_t got = 0;

	// Drain any bytes the handshake reader buffered past the Noise response
	// before touching the socket.
	if (fPendingOff < fPendingLen) {
		size_t avail = fPendingLen - fPendingOff;
		size_t take = avail < len ? avail : len;
		memcpy(buf, fPending + fPendingOff, take);
		fPendingOff += take;
		got += take;
	}

	while (got < len) {
		ssize_t n = fTls->Read(buf + got, len - got);
		if (n == -2) {
			// Receive timeout. Only retryable at a record boundary (nothing
			// read yet); mid-record it means a stalled peer, which is an error.
			return got == 0 ? B_WOULD_BLOCK : B_IO_ERROR;
		}
		if (n == 0)
			return got == 0 ? B_ENTRY_NOT_FOUND : B_IO_ERROR;
		if (n < 0)
			return B_IO_ERROR;
		got += (size_t)n;
	}
	return B_OK;
}

}	// namespace ts
