/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSTls.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


namespace ts {


TlsClient::TlsClient()
	:
	fSocket(-1),
	fCtx(NULL),
	fSsl(NULL),
	fInsecure(false),
	fLastError("")
{
}


TlsClient::~TlsClient()
{
	Close();
}


void
TlsClient::SetInsecure(bool insecure)
{
	fInsecure = insecure;
}


status_t
TlsClient::Connect(const char* host, uint16 port)
{
	if (host == NULL || *host == '\0')
		return B_BAD_VALUE;
	if (fSsl != NULL)
		return B_NOT_ALLOWED;	// already connected

	// --- resolve + TCP connect ---------------------------------------------
	char portStr[8];
	snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;		// v4 or v6 underlay is fine
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* results = NULL;
	if (getaddrinfo(host, portStr, &hints, &results) != 0 || results == NULL) {
		fLastError = "DNS resolution failed";
		return B_NAME_NOT_FOUND;
	}

	int sock = -1;
	for (struct addrinfo* ai = results; ai != NULL; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}
	freeaddrinfo(results);

	if (sock < 0) {
		_SetError("TCP connect");
		return B_ERROR;
	}
	fSocket = sock;

	// --- TLS handshake ------------------------------------------------------
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		_SetError("SSL_CTX_new");
		Close();
		return B_ERROR;
	}
	fCtx = ctx;

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	if (fInsecure) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_default_verify_paths(ctx);
	}

	SSL* ssl = SSL_new(ctx);
	if (ssl == NULL) {
		_SetError("SSL_new");
		Close();
		return B_ERROR;
	}
	fSsl = ssl;

	// SNI + verification hostname so the handshake targets the right vhost and
	// the certificate is checked against `host`.
	SSL_set_tlsext_host_name(ssl, host);
	if (!fInsecure) {
		X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
		X509_VERIFY_PARAM_set_hostflags(param,
			X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, host, 0);
	}

	SSL_set_fd(ssl, fSocket);
	if (SSL_connect(ssl) != 1) {
		_SetError("SSL_connect");
		Close();
		return B_ERROR;
	}

	return B_OK;
}


ssize_t
TlsClient::Write(const void* buf, size_t len)
{
	if (fSsl == NULL)
		return -1;
	int n = SSL_write((SSL*)fSsl, buf, (int)len);
	if (n <= 0) {
		_SetError("SSL_write");
		return -1;
	}
	return n;
}


ssize_t
TlsClient::Read(void* buf, size_t len)
{
	if (fSsl == NULL)
		return -1;
	int n = SSL_read((SSL*)fSsl, buf, (int)len);
	if (n > 0)
		return n;

	// Distinguish a clean shutdown (return 0) from a real error (-1).
	int err = SSL_get_error((SSL*)fSsl, n);
	if (err == SSL_ERROR_ZERO_RETURN)
		return 0;
	// A transport-level EOF (peer closed after sending, common with
	// Connection: close) surfaces as SSL_ERROR_SYSCALL with errno 0; treat it
	// as EOF rather than an error so read-to-end works.
	if (err == SSL_ERROR_SYSCALL && errno == 0)
		return 0;
	_SetError("SSL_read");
	return -1;
}


void
TlsClient::Close()
{
	if (fSsl != NULL) {
		SSL_shutdown((SSL*)fSsl);
		SSL_free((SSL*)fSsl);
		fSsl = NULL;
	}
	if (fCtx != NULL) {
		SSL_CTX_free((SSL_CTX*)fCtx);
		fCtx = NULL;
	}
	if (fSocket >= 0) {
		close(fSocket);
		fSocket = -1;
	}
}


void
TlsClient::_SetError(const char* context)
{
	unsigned long e = ERR_get_error();
	if (e != 0) {
		char buf[160];
		ERR_error_string_n(e, buf, sizeof(buf));
		fLastError.SetToFormat("%s: %s", context, buf);
	} else {
		fLastError.SetToFormat("%s: %s", context, strerror(errno));
	}
}


status_t
HttpsGet(const char* host, uint16 port, const char* path, bool insecure,
	int* outStatus, BString* outBody)
{
	if (host == NULL || path == NULL)
		return B_BAD_VALUE;

	TlsClient tls;
	tls.SetInsecure(insecure);
	status_t result = tls.Connect(host, port);
	if (result != B_OK)
		return result;

	BString req;
	req.SetToFormat(
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Sotoportego/0.1\r\n"
		"Accept: */*\r\n"
		"Connection: close\r\n\r\n",
		path, host);
	if (tls.Write(req.String(), req.Length()) < 0)
		return B_IO_ERROR;

	// Read the whole response (server closes after the body thanks to
	// Connection: close).
	BString raw;
	char chunk[4096];
	ssize_t n;
	while ((n = tls.Read(chunk, sizeof(chunk))) > 0)
		raw.Append(chunk, n);
	tls.Close();

	if (raw.Length() == 0)
		return B_IO_ERROR;

	// Parse the status line and split headers from body.
	if (outStatus != NULL) {
		*outStatus = 0;
		int sp = raw.FindFirst(' ');
		if (sp >= 0)
			*outStatus = atoi(raw.String() + sp + 1);
	}
	if (outBody != NULL) {
		int sep = raw.FindFirst("\r\n\r\n");
		if (sep >= 0)
			outBody->SetTo(raw.String() + sep + 4);
		else
			*outBody = raw;
	}
	return B_OK;
}

}	// namespace ts
