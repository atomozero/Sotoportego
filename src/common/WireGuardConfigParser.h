/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WIREGUARD_CONFIG_PARSER_H
#define WIREGUARD_CONFIG_PARSER_H


#include <string>

#include <String.h>
#include <SupportDefs.h>


// One [Peer] block. A client config normally has exactly one (the server it
// tunnels to); the parser keeps the first and ignores any others for now.
struct WireGuardPeer {
	BString		publicKey;			// base64, 32 bytes decoded
	BString		presharedKey;		// base64, optional (empty when absent)
	BString		endpointHost;		// hostname or IP literal
	uint16		endpointPort;		// 0 when the Endpoint line was missing
	BString		allowedIPs;			// raw, e.g. "0.0.0.0/0, ::/0"
	int32		persistentKeepalive;	// seconds, 0 = off

	WireGuardPeer()
		: endpointPort(0), persistentKeepalive(0) {}
};


// A parsed WireGuard configuration (the `wg-quick`/`.conf` INI format). Text
// fields are kept verbatim (still base64 for keys); decoding and validation of
// the key material is the backend's job once it wires in libsodium.
struct WireGuardConfig {
	// [Interface]
	BString			privateKey;		// base64, 32 bytes decoded
	BString			address;		// e.g. "10.2.0.2/32" (may be a list)
	BString			dns;			// optional
	uint16			listenPort;		// 0 = ephemeral
	int32			mtu;			// 0 = backend default

	// [Peer] -- first one only (see WireGuardPeer).
	WireGuardPeer	peer;

	WireGuardConfig()
		: listenPort(0), mtu(0) {}

	// Minimum needed to attempt a connection: our key, the peer's key, and
	// somewhere to send packets.
	bool IsComplete() const
	{
		return privateKey.Length() > 0
			&& peer.publicKey.Length() > 0
			&& peer.endpointHost.Length() > 0
			&& peer.endpointPort != 0;
	}
};


// Parses the wg-quick `.conf` INI format into a WireGuardConfig. Mirrors
// OpenVPNConfigParser: value-semantic, no ownership, tolerant of comments and
// CRLF. The backend passes the file through unchanged; this parser only fills
// the display/setup fields.
class WireGuardConfigParser {
public:
	// Parse from an in-memory string. Never fails hard: unknown keys and
	// malformed lines are skipped. Use WireGuardConfig::IsComplete() to decide
	// whether the result is usable.
	static	void	ParseText(const std::string& text, WireGuardConfig& config);

	// Read `path` and hand its contents to ParseText. Returns false only when
	// the file can't be read.
	static	bool	ParseFile(const char* path, WireGuardConfig& config);
};


#endif	// WIREGUARD_CONFIG_PARSER_H
