/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSNoise.h"

#include <string.h>

#include "WireGuardCrypto.h"


namespace ts {

// The Noise protocol name. 33 bytes -- longer than BLAKE2s' 32-byte digest, so
// per the Noise spec the initial hash is HASH(name) rather than the zero-padded
// name.
static const char kProtocolName[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";


NoiseIK::NoiseIK()
	:
	fHasKey(false),
	fN(0),
	fInitiator(false)
{
	memset(fCK, 0, sizeof(fCK));
	memset(fH, 0, sizeof(fH));
	memset(fK, 0, sizeof(fK));
	memset(fStaticPriv, 0, sizeof(fStaticPriv));
	memset(fStaticPub, 0, sizeof(fStaticPub));
	memset(fEphemeralPriv, 0, sizeof(fEphemeralPriv));
	memset(fEphemeralPub, 0, sizeof(fEphemeralPub));
	memset(fRemoteStatic, 0, sizeof(fRemoteStatic));
	memset(fRemoteEphemeral, 0, sizeof(fRemoteEphemeral));
}


// --- SymmetricState --------------------------------------------------------

void
NoiseIK::_InitSymmetric(const void* prologue, size_t prologueLen)
{
	// h = HASH(protocol_name); ck = h. (name is 33 bytes > 32-byte digest.)
	wg::Hash(kProtocolName, sizeof(kProtocolName) - 1, fH);
	memcpy(fCK, fH, 32);
	fHasKey = false;
	fN = 0;
	_MixHash(prologue, prologueLen);
}


void
NoiseIK::_MixHash(const void* data, size_t len)
{
	// h = HASH(h || data), streamed so we never concatenate into a temp buffer.
	wg::Blake2s state;
	wg::HashInit(state);
	wg::HashUpdate(state, fH, 32);
	if (len > 0)
		wg::HashUpdate(state, data, len);
	wg::HashFinal(state, fH);
}


void
NoiseIK::_MixKey(const uint8 input[32])
{
	// HKDF(ck, input) -> (ck', k). Kdf2 is exactly the 2-output HKDF chain.
	wg::Kdf2(fCK, input, 32, fCK, fK);
	fHasKey = true;
	fN = 0;
}


size_t
NoiseIK::_EncryptAndHash(const void* plain, size_t len, uint8* out)
{
	if (!fHasKey) {
		// No key yet (first token before any DH): the "ciphertext" is the
		// plaintext, still mixed into the transcript hash.
		if (len > 0)
			memcpy(out, plain, len);
		_MixHash(out, len);
		return len;
	}

	// AEAD with the transcript hash as associated data; nonce = fN.
	wg::AeadEncrypt(fK, fN, plain, len, fH, 32, out);
	fN++;
	size_t cipherLen = len + kNoiseTagLen;
	_MixHash(out, cipherLen);
	return cipherLen;
}


ssize_t
NoiseIK::_DecryptAndHash(const uint8* cipher, size_t len, uint8* out)
{
	if (!fHasKey) {
		if (len > 0)
			memcpy(out, cipher, len);
		_MixHash(cipher, len);
		return (ssize_t)len;
	}

	if (len < kNoiseTagLen)
		return -1;
	// MixHash absorbs the ciphertext; the AEAD verifies the tag against the
	// pre-decrypt hash as AAD, so snapshot h before mixing.
	uint8 aad[32];
	memcpy(aad, fH, 32);
	if (!wg::AeadDecrypt(fK, fN, cipher, len, aad, 32, out))
		return -1;
	fN++;
	_MixHash(cipher, len);
	return (ssize_t)(len - kNoiseTagLen);
}


// --- HandshakeState --------------------------------------------------------

void
NoiseIK::InitInitiator(const uint8 staticPriv[32], const uint8 staticPub[32],
	const uint8 remoteStaticPub[32], const void* prologue, size_t prologueLen)
{
	fInitiator = true;
	memcpy(fStaticPriv, staticPriv, 32);
	memcpy(fStaticPub, staticPub, 32);
	memcpy(fRemoteStatic, remoteStaticPub, 32);

	_InitSymmetric(prologue, prologueLen);
	// IK pre-message: the responder's static is known to the initiator, so it
	// is mixed into h during initialization.
	_MixHash(fRemoteStatic, 32);
}


void
NoiseIK::InitResponder(const uint8 staticPriv[32], const uint8 staticPub[32],
	const void* prologue, size_t prologueLen)
{
	fInitiator = false;
	memcpy(fStaticPriv, staticPriv, 32);
	memcpy(fStaticPub, staticPub, 32);

	_InitSymmetric(prologue, prologueLen);
	// Same pre-message from the responder's side: its own static public.
	_MixHash(fStaticPub, 32);
}


ssize_t
NoiseIK::WriteMessage1(const void* payload, size_t payloadLen, uint8* out,
	size_t outCap)
{
	if (!fInitiator)
		return -1;
	if (outCap < kNoiseMsg1Overhead + payloadLen)
		return -1;

	uint8* p = out;

	// -> e
	if (!wg::DhGenerate(fEphemeralPriv, fEphemeralPub))
		return -1;
	memcpy(p, fEphemeralPub, 32);
	_MixHash(fEphemeralPub, 32);
	p += 32;

	// es = DH(e, rs)
	uint8 dh[32];
	if (!wg::Dh(fEphemeralPriv, fRemoteStatic, dh))
		return -1;
	_MixKey(dh);

	// s (encrypted static)
	p += _EncryptAndHash(fStaticPub, 32, p);

	// ss = DH(s, rs)
	if (!wg::Dh(fStaticPriv, fRemoteStatic, dh))
		return -1;
	_MixKey(dh);

	// payload
	p += _EncryptAndHash(payload, payloadLen, p);

	return (ssize_t)(p - out);
}


ssize_t
NoiseIK::ReadMessage1(const uint8* in, size_t inLen, uint8* payloadOut,
	size_t payloadCap)
{
	if (fInitiator)
		return -1;
	// Minimum message 1 is e(32) + enc_static(48) + enc_empty_payload(16).
	if (inLen < 32 + 48 + kNoiseTagLen)
		return -1;

	const uint8* p = in;

	// -> e
	memcpy(fRemoteEphemeral, p, 32);
	_MixHash(fRemoteEphemeral, 32);
	p += 32;

	// es = DH(s, re)
	uint8 dh[32];
	if (!wg::Dh(fStaticPriv, fRemoteEphemeral, dh))
		return -1;
	_MixKey(dh);

	// s: decrypt the 48-byte encrypted static into fRemoteStatic
	if (_DecryptAndHash(p, 48, fRemoteStatic) != 32)
		return -1;
	p += 48;

	// ss = DH(s, rs)
	if (!wg::Dh(fStaticPriv, fRemoteStatic, dh))
		return -1;
	_MixKey(dh);

	// payload (the rest)
	size_t cipherLen = inLen - (size_t)(p - in);
	ssize_t plainLen = _DecryptAndHash(p, cipherLen, payloadOut);
	if (plainLen < 0 || (size_t)plainLen > payloadCap)
		return -1;
	return plainLen;
}


ssize_t
NoiseIK::WriteMessage2(const void* payload, size_t payloadLen, uint8* out,
	size_t outCap)
{
	if (fInitiator)
		return -1;
	if (outCap < kNoiseMsg2Overhead + payloadLen)
		return -1;

	uint8* p = out;

	// <- e
	if (!wg::DhGenerate(fEphemeralPriv, fEphemeralPub))
		return -1;
	memcpy(p, fEphemeralPub, 32);
	_MixHash(fEphemeralPub, 32);
	p += 32;

	// ee = DH(e, re)
	uint8 dh[32];
	if (!wg::Dh(fEphemeralPriv, fRemoteEphemeral, dh))
		return -1;
	_MixKey(dh);

	// se = DH(e, rs)  [responder ephemeral, initiator static]
	if (!wg::Dh(fEphemeralPriv, fRemoteStatic, dh))
		return -1;
	_MixKey(dh);

	// payload
	p += _EncryptAndHash(payload, payloadLen, p);

	return (ssize_t)(p - out);
}


ssize_t
NoiseIK::ReadMessage2(const uint8* in, size_t inLen, uint8* payloadOut,
	size_t payloadCap)
{
	if (!fInitiator)
		return -1;
	if (inLen < 32 + kNoiseTagLen)
		return -1;

	const uint8* p = in;

	// <- e
	memcpy(fRemoteEphemeral, p, 32);
	_MixHash(fRemoteEphemeral, 32);
	p += 32;

	// ee = DH(e, re)
	uint8 dh[32];
	if (!wg::Dh(fEphemeralPriv, fRemoteEphemeral, dh))
		return -1;
	_MixKey(dh);

	// se = DH(s, re)  [initiator static, responder ephemeral]
	if (!wg::Dh(fStaticPriv, fRemoteEphemeral, dh))
		return -1;
	_MixKey(dh);

	// payload
	size_t cipherLen = inLen - 32;
	ssize_t plainLen = _DecryptAndHash(p, cipherLen, payloadOut);
	if (plainLen < 0 || (size_t)plainLen > payloadCap)
		return -1;
	return plainLen;
}


bool
NoiseIK::Split(NoiseTransportKeys& keys) const
{
	// Split(): HKDF(ck, empty) -> (k1, k2). k1 is initiator->responder,
	// k2 is responder->initiator. Return the initiator's view either way.
	uint8 k1[32];
	uint8 k2[32];
	wg::Kdf2(fCK, NULL, 0, k1, k2);
	memcpy(keys.sendKey, k1, 32);
	memcpy(keys.recvKey, k2, 32);
	return true;
}

}	// namespace ts
