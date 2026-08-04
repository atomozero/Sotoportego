/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_DERP_H
#define TS_DERP_H


#include <stddef.h>
#include <sys/types.h>

#include <String.h>
#include <SupportDefs.h>

#include "TSTls.h"


// A DERP relay client. DERP (Designated Encrypted Relay for Packets) forwards
// already-WireGuard-encrypted packets between nodes that can't reach each other
// directly, and provides first-packet connectivity before the disco direct-path
// upgrade. One long-lived framed connection per home region.
//
// Wire protocol (tailscale/derp): after an HTTP Upgrade (`GET /derp`,
// `Upgrade: DERP`) the connection carries binary frames:
//     [type 1 byte][length uint32 big-endian][payload]
// The server opens with frameServerKey (magic "DERP🔑" + its 32-byte public
// key); the client replies with frameClientInfo (our node pub + nonce +
// NaCl-boxed JSON); thereafter frameSendPacket(dstKey, wg) and
// frameRecvPacket(srcKey, wg) relay packets, keyed by node public key.
namespace ts {

enum DerpFrameType {
	DERP_SERVER_KEY		= 0x01,
	DERP_CLIENT_INFO	= 0x02,
	DERP_SERVER_INFO	= 0x03,
	DERP_SEND_PACKET	= 0x04,
	DERP_RECV_PACKET	= 0x05,
	DERP_KEEP_ALIVE		= 0x06,
	DERP_NOTE_PREFERRED	= 0x07,
	DERP_PEER_GONE		= 0x08,
	DERP_PEER_PRESENT	= 0x09,
	DERP_PING			= 0x12,
	DERP_PONG			= 0x13,
	DERP_HEALTH			= 0x14,
	DERP_RESTARTING		= 0x15
};

static const size_t kDerpMagicLen	= 8;
static const size_t kDerpKeyLen		= 32;


class DerpClient {
public:
								DerpClient();
								~DerpClient();

			// Connect to a DERP server, do the HTTP upgrade, read the server
			// key, and send our clientInfo (identified by our node keypair).
			// Returns B_OK once the handshake frames are exchanged.
			status_t			Connect(const char* host, uint16 port,
									bool insecure, const uint8 nodePriv[32],
									const uint8 nodePub[32]);

			// Relay an (already WireGuard-encrypted) packet to a peer node key.
			status_t			SendPacket(const uint8 dstKey[32],
									const uint8* pkt, size_t len);
			// Receive the next relayed packet; sets srcKey and writes the packet
			// to `out`. Returns packet length, 0 if a non-packet control frame
			// was handled (call again), or -1 on error. Answers PING with PONG.
			ssize_t				RecvPacket(uint8 outSrcKey[32], uint8* out,
									size_t cap);

			// Close the relay connection (also unblocks a blocked RecvPacket).
			void				Close() { fTls.Close(); }

			const uint8*		ServerKey() const { return fServerKey; }
			const char*			LastError() const { return fLastError.String(); }

			status_t			WriteFrame(uint8 type, const uint8* payload,
									size_t len);
			status_t			ReadFrame(uint8* outType, uint8* buf,
									size_t cap, size_t* outLen);

private:
			status_t			_ReadUpgrade();
			status_t			_ReadRaw(uint8* dst, size_t n);
			status_t			_Fill(size_t need);

			TlsClient			fTls;
			uint8				fServerKey[32];
			uint8				fNodePriv[32];
			uint8				fNodePub[32];
			BString				fLastError;

			uint8				fBuf[65536];
			size_t				fBufOff;
			size_t				fBufLen;
};

}	// namespace ts


#endif	// TS_DERP_H
