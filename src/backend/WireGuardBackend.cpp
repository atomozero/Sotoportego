/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WireGuardBackend.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <MessageRunner.h>

#include "TunDevice.h"
#include "VPNProfile.h"
#include "WireGuardCrypto.h"


// Decode standard base64 into `out` (capacity `outCap`), reporting the byte
// count in `outLen`. Returns false on a stray character or overflow. WireGuard
// keys are always 32 bytes; callers check outLen themselves.
static bool
base64_decode(const BString& in, uint8* out, size_t outCap, size_t& outLen)
{
	static int rev[256];
	static bool ready = false;
	if (!ready) {
		for (int i = 0; i < 256; i++)
			rev[i] = -1;
		const char* alpha =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for (int i = 0; i < 64; i++)
			rev[(unsigned char)alpha[i]] = i;
		ready = true;
	}

	uint32 buffer = 0;
	int bits = 0;
	outLen = 0;
	for (const char* p = in.String(); *p != '\0'; p++) {
		unsigned char c = (unsigned char)*p;
		if (c == '=')
			break;
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			continue;
		int v = rev[c];
		if (v < 0)
			return false;
		buffer = (buffer << 6) | (uint32)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (outLen >= outCap)
				return false;
			out[outLen++] = (uint8)((buffer >> bits) & 0xFF);
		}
	}
	return true;
}


WireGuardBackend::WireGuardBackend()
	:
	VPNBackend("WireGuardBackend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fConfig(),
	fHavePresharedKey(false),
	fLocalIP(),
	fRemoteIP(),
	fTunInterface(),
	fTunNode(),
	fUdpSocket(-1),
	fReader(-1),
	fTimer(NULL),
	fStopRequested(false)
{
	memset(fPrivateKey, 0, sizeof(fPrivateKey));
	memset(fPeerPublicKey, 0, sizeof(fPeerPublicKey));
	memset(fPresharedKey, 0, sizeof(fPresharedKey));
	memset(fEphemeralPrivate, 0, sizeof(fEphemeralPrivate));
	memset(fEphemeralPublic, 0, sizeof(fEphemeralPublic));
	memset(fChainingKey, 0, sizeof(fChainingKey));
	memset(fHash, 0, sizeof(fHash));
	fSenderIndex = 0;
	fReceiverIndex = 0;
	memset(fSendKey, 0, sizeof(fSendKey));
	memset(fRecvKey, 0, sizeof(fRecvKey));
}


WireGuardBackend::~WireGuardBackend()
{
	_Cleanup();
}


status_t
WireGuardBackend::Connect(const VPNProfile& profile)
{
	if (fState != VPN_STATE_DISCONNECTED && fState != VPN_STATE_ERROR)
		return B_NOT_ALLOWED;

	if (Looper() == NULL) {
		// The backend must be attached to the daemon's looper before use, so
		// BMessenger(this) (for timer ticks) is addressable.
		return B_NO_INIT;
	}

	if (profile.fConfigPath.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "profile has no WireGuard config path");
		return B_BAD_VALUE;
	}

	// Load and validate the .conf up front so a broken profile fails cleanly.
	fConfig = WireGuardConfig();
	if (!WireGuardConfigParser::ParseFile(profile.fConfigPath.String(),
			fConfig)) {
		_SetState(VPN_STATE_ERROR, "cannot read WireGuard config");
		return B_ERROR;
	}
	if (!fConfig.IsComplete()) {
		_SetState(VPN_STATE_ERROR,
			"WireGuard config is missing a key or endpoint");
		return B_BAD_VALUE;
	}

	fRemoteIP = fConfig.peer.endpointHost;
	fLocalIP = fConfig.address;		// display value; refined once tun is up
	fStopRequested = false;
	fStats.Reset();

	// Step 1: turn the base64 key material into raw bytes up front, so a
	// mistyped key fails before we touch the system.
	if (!_DecodeKeys()) {
		_SetState(VPN_STATE_ERROR, "WireGuard config has an invalid key");
		return B_BAD_VALUE;
	}

	_SetState(VPN_STATE_CONNECTING);

	printf("[WireGuard] connecting '%s' -> %s:%u\n", profile.fName.String(),
		fConfig.peer.endpointHost.String(),
		(unsigned)fConfig.peer.endpointPort);

	// Step 2: bring up a tun slot with our Address and bind a UDP socket to
	// the peer endpoint.
	if (!_BringUpTun()) {
		_Cleanup();
		_SetState(VPN_STATE_ERROR, "could not bring up a tun slot");
		return B_ERROR;
	}
	if (!_OpenUdpSocket()) {
		_Cleanup();
		_SetState(VPN_STATE_ERROR,
			"could not reach the WireGuard endpoint");
		return B_ERROR;
	}

	// Step 3: the Noise IK handshake. On success we hold the transport keys.
	if (!_PerformHandshake()) {
		_Cleanup();
		_SetState(VPN_STATE_ERROR, "WireGuard handshake failed");
		return B_ERROR;
	}
	printf("[WireGuard] handshake OK (session %u <-> %u)\n",
		(unsigned)fSenderIndex, (unsigned)fReceiverIndex);

	// TODO(wireguard) step 4: _StartReader() forwards tun<->UDP with fSendKey/
	// fRecvKey and arms the rekey/keepalive timers, ending in CONNECTED and a
	// B_OK return. Until then the handshake is proven but no traffic flows, so
	// tear the plumbing down rather than claim a live tunnel.
	_Cleanup();
	_SetState(VPN_STATE_ERROR,
		"WireGuard transport not yet implemented (handshake OK)");
	return B_ERROR;
}


status_t
WireGuardBackend::Disconnect()
{
	if (fState == VPN_STATE_DISCONNECTED)
		return B_OK;

	fStopRequested = true;
	_Cleanup();
	_SetState(VPN_STATE_DISCONNECTED);
	return B_OK;
}


VPNState
WireGuardBackend::State() const
{
	return fState;
}


VPNStats
WireGuardBackend::Stats() const
{
	return fStats;
}


const char*
WireGuardBackend::BackendName() const
{
	return "WireGuard";
}


BString
WireGuardBackend::LocalIP() const
{
	return fLocalIP;
}


BString
WireGuardBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
WireGuardBackend::MessageReceived(BMessage* message)
{
	switch (message->what) {
		// TODO(wireguard): handshake-retransmit / rekey / keepalive timer
		// ticks (posted by fTimer) and reader-thread events dispatch here.
		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


void
WireGuardBackend::RecoverIfCrashed()
{
	// TODO(wireguard): if a previous run died with a tun slot up and routes
	// installed, roll them back here (mirrors OpenVPNBackend::RecoverIfCrashed).
}


void
WireGuardBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	NotifyStateChanged(state, detail);
}


bool
WireGuardBackend::_DecodeKeys()
{
	size_t n = 0;
	if (!base64_decode(fConfig.privateKey, fPrivateKey, sizeof(fPrivateKey), n)
			|| n != sizeof(fPrivateKey)) {
		fprintf(stderr, "[WireGuard] bad Interface PrivateKey\n");
		return false;
	}
	if (!base64_decode(fConfig.peer.publicKey, fPeerPublicKey,
			sizeof(fPeerPublicKey), n) || n != sizeof(fPeerPublicKey)) {
		fprintf(stderr, "[WireGuard] bad Peer PublicKey\n");
		return false;
	}

	fHavePresharedKey = false;
	if (fConfig.peer.presharedKey.Length() > 0) {
		if (!base64_decode(fConfig.peer.presharedKey, fPresharedKey,
				sizeof(fPresharedKey), n) || n != sizeof(fPresharedKey)) {
			fprintf(stderr, "[WireGuard] bad Peer PresharedKey\n");
			return false;
		}
		fHavePresharedKey = true;
	}
	return true;
}


// --- data plane (handshake/transport still TODO(wireguard)) -----------------

bool
WireGuardBackend::_BringUpTun()
{
	if (!TunDevice::ProbeFreeSlot(fTunInterface, fTunNode))
		return false;

	// Assign the [Interface] Address. WG configs give a CIDR ("10.2.0.2/32");
	// take the address part and set it as a point-to-point self so packets for
	// AllowedIPs can be routed onto tun/N later. IPv4 only for now.
	// TODO(wireguard): handle IPv6 Address lines and multiple addresses.
	BString ip = fConfig.address;
	int32 slash = ip.FindFirst('/');
	if (slash >= 0)
		ip.Truncate(slash);
	ip.Trim();
	if (ip.Length() == 0)
		return true;		// no address to assign; the slot is up

	BString mtu;
	mtu << (fConfig.mtu > 0 ? fConfig.mtu : 1420);	// WireGuard default MTU
	const char* const ifconfigAddr[] = {
		"ifconfig", fTunInterface.String(), "inet",
		ip.String(), ip.String(), "mtu", mtu.String(), "up", NULL
	};
	return TunDevice::RunIfconfig(ifconfigAddr);
}


bool
WireGuardBackend::_OpenUdpSocket()
{
	// IPv4 endpoints only for now (matches _BringUpTun).
	// TODO(wireguard): AF_INET6 endpoints.
	struct hostent* he = gethostbyname(fConfig.peer.endpointHost.String());
	if (he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL
			|| he->h_addrtype != AF_INET
			|| he->h_length != (int)sizeof(struct in_addr)) {
		fprintf(stderr, "[WireGuard] cannot resolve endpoint %s\n",
			fConfig.peer.endpointHost.String());
		return false;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return false;
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(fConfig.peer.endpointPort);
	memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

	// connect() the datagram socket so send()/recv() default to the endpoint
	// and the kernel drops packets from anywhere else.
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(fd);
		return false;
	}

	fUdpSocket = fd;
	return true;
}


static void
store32_le(uint8* p, uint32 v)
{
	p[0] = (uint8)v; p[1] = (uint8)(v >> 8);
	p[2] = (uint8)(v >> 16); p[3] = (uint8)(v >> 24);
}


static uint32
load32_le(const uint8* p)
{
	return (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
}


// H = Hash(H || data)
static void
mix_hash(uint8 h[32], const void* data, size_t len)
{
	wg::Blake2s s;
	wg::HashInit(s);
	wg::HashUpdate(s, h, 32);
	wg::HashUpdate(s, data, len);
	wg::HashFinal(s, h);
}


bool
WireGuardBackend::_PerformHandshake()
{
	// WireGuard's Noise_IKpsk2 handshake, following the whitepaper. Every
	// primitive below is validated against its test vector; the assembly here
	// is what still needs proving against a real peer.
	static const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
	static const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
	static const uint8 kLabelMac1[8] = { 'm', 'a', 'c', '1', '-', '-', '-', '-' };

	uint8 staticPub[32];
	if (!wg::DhPublic(fPrivateKey, staticPub))
		return false;

	// C = Hash(CONSTRUCTION); H = Hash(Hash(C || IDENTIFIER) || Spub_r)
	wg::Hash(kConstruction, strlen(kConstruction), fChainingKey);
	{
		wg::Blake2s s;
		wg::HashInit(s);
		wg::HashUpdate(s, fChainingKey, 32);
		wg::HashUpdate(s, kIdentifier, strlen(kIdentifier));
		wg::HashFinal(s, fHash);
	}
	mix_hash(fHash, fPeerPublicKey, 32);

	// --- initiation ---
	if (!wg::DhGenerate(fEphemeralPrivate, fEphemeralPublic))
		return false;
	wg::Kdf1(fChainingKey, fEphemeralPublic, 32, fChainingKey);
	mix_hash(fHash, fEphemeralPublic, 32);

	uint8 dh[32];
	uint8 key[32];

	// encrypted_static
	if (!wg::Dh(fEphemeralPrivate, fPeerPublicKey, dh))
		return false;
	wg::Kdf2(fChainingKey, dh, 32, fChainingKey, key);
	uint8 encStatic[48];
	if (!wg::AeadEncrypt(key, 0, staticPub, 32, fHash, 32, encStatic))
		return false;
	mix_hash(fHash, encStatic, 48);

	// encrypted_timestamp
	if (!wg::Dh(fPrivateKey, fPeerPublicKey, dh))
		return false;
	wg::Kdf2(fChainingKey, dh, 32, fChainingKey, key);
	uint8 timestamp[12];
	wg::Tai64n(timestamp);
	uint8 encTs[28];
	if (!wg::AeadEncrypt(key, 0, timestamp, 12, fHash, 32, encTs))
		return false;
	mix_hash(fHash, encTs, 28);

	// Assemble the 148-byte initiation message.
	if (!wg::RandomBytes(&fSenderIndex, sizeof(fSenderIndex)))
		return false;
	uint8 msg[148];
	memset(msg, 0, sizeof(msg));
	msg[0] = 1;								// message_type
	store32_le(msg + 4, fSenderIndex);
	memcpy(msg + 8, fEphemeralPublic, 32);
	memcpy(msg + 40, encStatic, 48);
	memcpy(msg + 88, encTs, 28);
	// mac1 = MAC(Hash(LABEL_MAC1 || Spub_r), msg[0:116]); mac2 stays zero.
	uint8 mac1Key[32];
	{
		wg::Blake2s s;
		wg::HashInit(s);
		wg::HashUpdate(s, kLabelMac1, sizeof(kLabelMac1));
		wg::HashUpdate(s, fPeerPublicKey, 32);
		wg::HashFinal(s, mac1Key);
	}
	wg::Mac16(mac1Key, msg, 116, msg + 116);

	if (send(fUdpSocket, msg, sizeof(msg), 0) != (ssize_t)sizeof(msg)) {
		fprintf(stderr, "[WireGuard] failed to send handshake initiation\n");
		return false;
	}

	// --- response ---
	// Bounded blocking wait. TODO(wireguard) step 4: move onto the reader
	// thread and retransmit the initiation until this lands.
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(fUdpSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	uint8 resp[256];
	ssize_t got = recv(fUdpSocket, resp, sizeof(resp), 0);
	if (got != 92 || resp[0] != 2) {
		fprintf(stderr,
			"[WireGuard] no/invalid handshake response (got %ld bytes)\n",
			(long)got);
		return false;
	}
	if (load32_le(resp + 8) != fSenderIndex) {
		fprintf(stderr, "[WireGuard] handshake response index mismatch\n");
		return false;
	}
	fReceiverIndex = load32_le(resp + 4);
	const uint8* peerEphemeral = resp + 12;
	const uint8* encNothing = resp + 44;	// 16 bytes: empty plaintext + tag

	wg::Kdf1(fChainingKey, peerEphemeral, 32, fChainingKey);
	mix_hash(fHash, peerEphemeral, 32);
	if (!wg::Dh(fEphemeralPrivate, peerEphemeral, dh))	// ee
		return false;
	wg::Kdf1(fChainingKey, dh, 32, fChainingKey);
	if (!wg::Dh(fPrivateKey, peerEphemeral, dh))		// se
		return false;
	wg::Kdf1(fChainingKey, dh, 32, fChainingKey);

	uint8 psk[32];
	if (fHavePresharedKey)
		memcpy(psk, fPresharedKey, 32);
	else
		memset(psk, 0, 32);
	uint8 tau[32];
	wg::Kdf3(fChainingKey, psk, 32, fChainingKey, tau, key);
	mix_hash(fHash, tau, 32);

	uint8 empty[1];
	if (!wg::AeadDecrypt(key, 0, encNothing, 16, fHash, 32, empty)) {
		fprintf(stderr,
			"[WireGuard] handshake response failed to authenticate\n");
		return false;
	}
	mix_hash(fHash, encNothing, 16);

	// Derive transport keys: initiator send/recv = KDF2(C, empty).
	wg::Kdf2(fChainingKey, NULL, 0, fSendKey, fRecvKey);
	return true;
}


void
WireGuardBackend::_StartReader()
{
	// TODO(wireguard): spawn _ReaderEntry to forward tun<->UDP once transport
	// keys are live, and post CONNECTED from there.
}


int32
WireGuardBackend::_RunReaderLoop()
{
	// TODO(wireguard): read tun -> encrypt -> UDP, and UDP -> decrypt -> tun,
	// until fStopRequested; post state/stats back to the looper.
	return 0;
}


int32
WireGuardBackend::_ReaderEntry(void* self)
{
	return ((WireGuardBackend*)self)->_RunReaderLoop();
}


void
WireGuardBackend::_Cleanup()
{
	// TODO(wireguard): join the reader thread and remove installed routes.
	delete fTimer;
	fTimer = NULL;

	if (fUdpSocket >= 0) {
		close(fUdpSocket);
		fUdpSocket = -1;
	}

	if (fTunInterface.Length() > 0) {
		// --delete removes the interface entirely; the kernel tunnel add-on
		// republishes the slot next time it's ifconfig'd up.
		const char* const ifconfigDelete[] = {
			"ifconfig", "--delete", fTunInterface.String(), NULL
		};
		TunDevice::RunIfconfig(ifconfigDelete);
		fTunInterface = "";
		fTunNode = "";
	}
}
