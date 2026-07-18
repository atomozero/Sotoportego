/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef WIREGUARD_BACKEND_H
#define WIREGUARD_BACKEND_H


#include <sys/types.h>

#include <OS.h>
#include <String.h>

#include "VPNBackend.h"
#include "WireGuardConfigParser.h"

class BMessageRunner;


// WireGuard backend -- in-process data plane.
//
// Unlike OpenVPNBackend, this drives no external binary (Haiku has no packaged
// `wg`/wireguard-go): it speaks the protocol itself. Progress by step:
//
//   1. DONE -- base64-decode the key material.
//   2. DONE -- bring up a tun/N slot (via TunDevice), bind a UDP socket.
//   3. DONE -- the Noise_IKpsk2 handshake (see WireGuardCrypto), validated
//      against a reference responder.
//   4. DONE -- transport: a reader thread runs the handshake, then forwards
//      tun<->UDP, encrypting/decrypting type-4 data messages, sending
//      PersistentKeepalives, and posting CONNECTED.
//   5. DONE -- install AllowedIPs as routes (via TunDevice), pinning the
//      endpoint to the carrier for a full tunnel; plus session rekey (~120s)
//      and an RFC 6479 anti-replay window.
//
// The protocol is complete and validated against a real WireGuard server
// (handshake + transport); what still needs on-device confirmation is Haiku's
// tun read/write framing. State mutations stay on the daemon looper: the reader
// thread posts private messages (connected / stats / exited) back via
// BMessenger(this), mirroring OpenVPNBackend.
class WireGuardBackend : public VPNBackend {
public:
								WireGuardBackend();
	virtual						~WireGuardBackend();

	virtual	status_t			Connect(const VPNProfile& profile);
	virtual	status_t			Disconnect();
	virtual	VPNState			State() const;
	virtual	VPNStats			Stats() const;
	virtual	const char*			BackendName() const;
	virtual	BString				LocalIP() const;
	virtual	BString				RemoteIP() const;

	virtual	void				MessageReceived(BMessage* message);

	virtual	void				RecoverIfCrashed();

private:
			void				_SetState(VPNState state,
									const char* detail = NULL);

	// Base64-decode the config's key material into the fixed 32-byte buffers
	// below, validating each length. Returns false on any malformed key.
			bool				_DecodeKeys();

	// --- data plane (handshake/transport still TODO(wireguard)) ---------
	// Bring up the first free tun/N slot (via TunDevice) and assign the
	// [Interface] Address to it.
			bool				_BringUpTun();
	// Bind a UDP socket toward the [Peer] Endpoint.
			bool				_OpenUdpSocket();
	// Open the /dev/tun/N node for reading/writing IP packets.
			bool				_OpenTunFd();
	// Run the Noise IK handshake. Returns true once transport keys are set.
			bool				_PerformHandshake();

	// Wrap a plaintext IP packet (or 0 bytes for a keepalive) into a type-4
	// transport message using fSendKey and the next send counter. `out` needs
	// room for 16 + roundup16(plainLen) + 16 bytes; the total is returned.
			size_t				_Encapsulate(const uint8* plain,
									size_t plainLen, uint8* out);
	// Decrypt a received type-4 message with fRecvKey into `out` (needs
	// packetLen bytes). Returns the plaintext IP-packet length (0 for a
	// keepalive) or -1 if the packet isn't valid or is a replay.
			ssize_t				_Decapsulate(const uint8* packet,
									size_t packetLen, uint8* out);

	// Anti-replay sliding window (RFC 6479) over the received transport
	// counters. _ReplayReset clears it at each (re)handshake; _ReplayValidate
	// accepts-and-records a fresh counter or rejects an old/duplicate one.
			void				_ReplayReset();
			bool				_ReplayValidate(uint64 counter);

	// Install / remove the AllowedIPs routes (and, for a full tunnel, the
	// endpoint pin + default-route swap), all via TunDevice::RunRoute.
			void				_InstallRoutes();
			void				_RemoveRoutes();

	// Reader thread: handshake, then tun<->UDP forwarding until stopped.
			void				_StartReader();
			int32				_RunReaderLoop();
	static	int32				_ReaderEntry(void* self);
	// Tear everything down: thread, sockets, tun slot.
			void				_Cleanup();

			VPNState			fState;
			VPNStats			fStats;
			WireGuardConfig		fConfig;
	// Raw key material, base64-decoded from fConfig by _DecodeKeys().
			uint8				fPrivateKey[32];
			uint8				fPeerPublicKey[32];
			uint8				fPresharedKey[32];
			bool				fHavePresharedKey;

	// Noise handshake state (filled by _PerformHandshake).
			uint8				fEphemeralPrivate[32];
			uint8				fEphemeralPublic[32];
			uint8				fChainingKey[32];
			uint8				fHash[32];
			uint32				fSenderIndex;	// our session index (Ii)
			uint32				fReceiverIndex;	// peer's session index (Ir)
	// Transport keys derived once the handshake completes; consumed by the
	// data-plane reader in step 4.
			uint8				fSendKey[32];
			uint8				fRecvKey[32];

			BString				fLocalIP;		// in-tunnel Address
			BString				fRemoteIP;		// Endpoint host

	// Haiku tunnel slot, picked at Connect time (see OpenVPNBackend for the
	// probing rationale). "tun/N" for ifconfig/route, "/dev/tun/N" for the node.
			BString				fTunInterface;
			BString				fTunNode;
	// Resolved endpoint IP (pinned to the carrier) and the address we put on
	// the tun (used as the on-link next hop for AllowedIPs routes).
			BString				fEndpointIP;
			BString				fTunSelfIP;
	// Routing teardown state.
			bool				fRoutesInstalled;
			bool				fReplacedDefault;
			BString				fOrigGateway;
			BString				fOrigGatewayIface;

			int					fUdpSocket;		// -1 when none
			int					fTunFd;			// /dev/tun/N, -1 when none
			thread_id			fReader;		// -1 when no thread alive
	// Monotonic per-packet counter for the transport nonce (send direction).
			uint64				fSendCounter;
	// Receive-side anti-replay window: fReplayCounter is the highest counter
	// seen (1-based), fReplayBitmap the 8192-bit seen-set (RFC 6479).
			uint64				fReplayCounter;
			uint64				fReplayBitmap[128];
	// Reserved for a future keepalive BMessageRunner. NULL when idle.
			BMessageRunner*		fTimer;
			bool				fStopRequested;
};


#endif	// WIREGUARD_BACKEND_H
