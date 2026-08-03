/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_CONTROL_CONN_H
#define TS_CONTROL_CONN_H


#include <stddef.h>
#include <sys/types.h>

#include <SupportDefs.h>

#include "TSNoise.h"

namespace ts {

class TlsClient;


// The encrypted record stream that runs over the ts2021 control channel once
// the Noise handshake has completed. It sits between the raw TLS byte stream
// (TlsClient) and the control RPCs (HTTP/2 requests carrying RegisterRequest /
// MapRequest), transparently sealing/opening Tailscale "record" frames.
//
// Record framing (control/controlbase): each record is
//     [type=4][ciphertext length, big-endian uint16][ciphertext]
// where the ciphertext is ChaCha20-Poly1305(plaintext) with the 16-byte tag
// appended and NO associated data. Note the transport nonce differs from the
// handshake's: it is a 12-byte nonce whose low 8 bytes hold a per-direction
// counter in BIG-endian (bytes 0..3 zero), each direction starting at 0. Max
// plaintext per record is 4077 bytes; WriteMessage splits larger buffers.
class ControlConn {
public:
								ControlConn();

			// Bind to an already-handshaked TLS stream and its transport keys
			// (initiator view: sendKey seals our writes, recvKey opens reads).
			// `pending`/`pendingLen` are any record-stream bytes the handshake
			// reader already pulled off the socket past the Noise response;
			// they are consumed before reading more from the TLS stream so the
			// first record isn't split.
			void				Init(TlsClient* tls,
									const NoiseTransportKeys& keys,
									const uint8* pending = NULL,
									size_t pendingLen = 0);

			// Seal `len` bytes into one or more records and write them to the
			// stream. Returns B_OK or an error.
			status_t			WriteMessage(const void* data, size_t len);

			// Read and open exactly one record, writing the plaintext to `buf`.
			// Returns the plaintext length, 0 on clean EOF, or -1 on error /
			// authentication failure.
			ssize_t				ReadRecord(uint8* buf, size_t cap);

private:
			status_t			_ReadFull(uint8* buf, size_t len);

			TlsClient*			fTls;
			uint8				fTxKey[32];
			uint8				fRxKey[32];
			uint64				fTxCounter;
			uint64				fRxCounter;

			// Bytes read past the Noise response by the handshake, drained
			// before the TLS stream. Sized for a couple of max records.
			uint8				fPending[8192];
			size_t				fPendingLen;
			size_t				fPendingOff;
};

}	// namespace ts


#endif	// TS_CONTROL_CONN_H
