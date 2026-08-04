/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_TLS_H
#define TS_TLS_H


#include <stddef.h>
#include <sys/types.h>

#include <Locker.h>
#include <String.h>
#include <SupportDefs.h>


// A thin blocking TLS client over a Haiku BSD socket, wrapping OpenSSL (already
// linked for the WireGuard X25519/ChaCha work). It is the transport under two
// things in the Tailscale backend:
//
//   * the one-shot HTTPS GET of `<control>/key`, which returns the control
//     server's Noise static public key (the `remoteStaticPub` the ts2021
//     handshake pins), and
//   * later, the long-lived `POST <control>/ts2021` stream that carries the
//     framed Noise handshake + control messages, and the DERP TLS connections.
//
// Security note: for the ts2021 channel the real authentication is the Noise IK
// handshake against the *pinned* control key, not the outer TLS certificate --
// which is why Tailscale can run this over otherwise-unverified TLS. The initial
// `/key` fetch, however, is only as trustworthy as the TLS it rides on (a MITM
// there could substitute a key), so Connect() verifies the peer certificate by
// default; SetInsecure(true) disables it for self-hosted Headscale with a
// private CA / pinned key configured out of band.
namespace ts {

class TlsClient {
public:
								TlsClient();
								~TlsClient();

			// Opt out of certificate verification before Connect(). Intended
			// for self-hosted control servers whose key is trusted by other
			// means; leaves the default (verify) untouched otherwise.
			void				SetInsecure(bool insecure);

			// Resolve host, open a TCP connection to host:port, and run the TLS
			// handshake with SNI = host. Returns B_OK or an error.
			status_t			Connect(const char* host, uint16 port);

			// Override the receive timeout (default 30s from Connect). A short
			// timeout lets a reader thread release the I/O lock promptly so a
			// concurrent writer isn't starved -- needed for DERP, where one
			// thread reads while another sends.
			void				SetReadTimeout(int seconds);

			// Blocking write/read of application data over the TLS session.
			// Return bytes transferred, 0 on clean EOF (read), or -1 on error
			// (-2 on a receive timeout). Read and Write serialise on an internal
			// lock: OpenSSL forbids concurrent access to one SSL object.
			ssize_t				Write(const void* buf, size_t len);
			ssize_t				Read(void* buf, size_t len);

			void				Close();
			bool				IsConnected() const { return fSsl != NULL; }

			// Last human-readable error (OpenSSL string or errno message),
			// for logging.
			const char*			LastError() const { return fLastError.String(); }

private:
			void				_SetError(const char* context);

			int					fSocket;
			void*				fCtx;	// SSL_CTX* (kept void* to avoid leaking
			void*				fSsl;	// SSL*      the OpenSSL headers here)
			bool				fInsecure;
			BString				fLastError;
			BLocker				fIoLock;	// serialises SSL_read / SSL_write
};


// Minimal one-shot HTTPS GET, blocking. Opens a TlsClient, sends an HTTP/1.1
// request with `Connection: close`, reads the whole response, and splits status
// / body. Adequate for the small `/key` document; it does not decode chunked
// transfer-encoding (the control key endpoint returns a plain body). Returns
// B_OK with outStatus / outBody filled, or an error.
status_t HttpsGet(const char* host, uint16 port, const char* path,
			bool insecure, int* outStatus, BString* outBody);

}	// namespace ts


#endif	// TS_TLS_H
