/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WireGuardBackend.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <vector>

#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>

#include "TunDevice.h"
#include "VPNProfile.h"
#include "WireGuardCrypto.h"


// Private 'what' codes the reader thread posts back to the looper, so all
// state mutations happen on one thread (mirrors OpenVPNBackend).
static const uint32 kMsgWgConnected		= 'wgCo';
static const uint32 kMsgWgStats			= 'wgSt';
static const uint32 kMsgWgReaderExited	= 'wgRx';

// PersistentKeepalive fallback and the reader's poll cadence.
static const bigtime_t kReaderPollInterval	= 250000;	// 0.25s select timeout
static const int kHandshakeAttempts			= 3;


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
	fEndpointIP(),
	fTunSelfIP(),
	fRoutesInstalled(false),
	fReplacedDefault(false),
	fOrigGateway(),
	fOrigGatewayIface(),
	fUdpSocket(-1),
	fTunFd(-1),
	fReader(-1),
	fSendCounter(0),
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
	if (!_OpenTunFd()) {
		_Cleanup();
		_SetState(VPN_STATE_ERROR, "could not open the tun device");
		return B_ERROR;
	}

	// Hand off to the reader thread: it runs the handshake and then the
	// transport loop, posting CONNECTED / stats / exit back to the looper.
	// Keeping the blocking work off the looper mirrors OpenVPNBackend.
	_StartReader();
	if (fReader < 0) {
		_Cleanup();
		_SetState(VPN_STATE_ERROR, "could not start the WireGuard worker");
		return B_ERROR;
	}
	return B_OK;
}


status_t
WireGuardBackend::Disconnect()
{
	if (fState == VPN_STATE_DISCONNECTED)
		return B_OK;

	fStopRequested = true;
	if (fReader < 0) {
		// No worker running (e.g. a failed connect); tear down here.
		_Cleanup();
		_SetState(VPN_STATE_DISCONNECTED);
	}
	// Otherwise the reader notices fStopRequested within a poll interval,
	// exits, and kMsgWgReaderExited settles the state on Disconnected.
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
		case kMsgWgConnected:
			// Steer traffic into the tunnel now that transport keys are live.
			_InstallRoutes();
			_SetState(VPN_STATE_CONNECTED);
			break;

		case kMsgWgStats:
		{
			int64 in = 0;
			int64 out = 0;
			message->FindInt64("in", &in);
			message->FindInt64("out", &out);
			fStats.fBytesIn = (uint64)in;
			fStats.fBytesOut = (uint64)out;
			NotifyStats(fStats);
			break;
		}

		case kMsgWgReaderExited:
		{
			// The reader has stopped (clean, error, or Disconnect). Join it and
			// settle the state; detail is empty for a clean stop.
			const char* detail = NULL;
			message->FindString("detail", &detail);
			_Cleanup();
			if (detail != NULL && detail[0] != '\0')
				_SetState(VPN_STATE_ERROR, detail);
			else
				_SetState(VPN_STATE_DISCONNECTED);
			break;
		}

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
	fTunSelfIP = ip;		// used as the on-link next hop for AllowedIPs routes
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
	fEndpointIP = inet_ntoa(addr.sin_addr);		// pinned to the carrier later

	// connect() the datagram socket so send()/recv() default to the endpoint
	// and the kernel drops packets from anywhere else.
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(fd);
		return false;
	}

	fUdpSocket = fd;
	return true;
}


bool
WireGuardBackend::_OpenTunFd()
{
	// Open the character device the kernel tunnel add-on published when
	// _BringUpTun ifconfig'd the slot up; IP packets are read/written raw.
	// TODO(wireguard): confirm Haiku's tun framing (raw IP vs a leading
	// address-family word) against a live capture -- this assumes raw IP,
	// like openvpn's --dev-node path.
	fTunFd = open(fTunNode.String(), O_RDWR);
	if (fTunFd < 0) {
		fprintf(stderr, "[WireGuard] cannot open %s\n", fTunNode.String());
		return false;
	}
	fcntl(fTunFd, F_SETFD, FD_CLOEXEC);
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


static void
store64_le(uint8* p, uint64 v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (uint8)(v >> (8 * i));
}


static uint64
load64_le(const uint8* p)
{
	uint64 v = 0;
	for (int i = 0; i < 8; i++)
		v |= (uint64)p[i] << (8 * i);
	return v;
}


// Length of the IP packet at `pkt` (up to `maxLen`), used to strip the zero
// padding WireGuard adds before encryption. Falls back to maxLen for anything
// that isn't a recognisable IPv4/IPv6 header.
static size_t
ip_packet_length(const uint8* pkt, size_t maxLen)
{
	if (maxLen == 0)
		return 0;
	int version = pkt[0] >> 4;
	if (version == 4 && maxLen >= 20) {
		size_t total = ((size_t)pkt[2] << 8) | pkt[3];
		return total <= maxLen ? total : maxLen;
	}
	if (version == 6 && maxLen >= 40) {
		size_t payload = ((size_t)pkt[4] << 8) | pkt[5];
		size_t total = 40 + payload;
		return total <= maxLen ? total : maxLen;
	}
	return maxLen;
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


size_t
WireGuardBackend::_Encapsulate(const uint8* plain, size_t plainLen, uint8* out)
{
	// Pad the plaintext up to a multiple of 16; a keepalive (plainLen 0) stays
	// at 0 and encrypts to a bare 16-byte tag.
	size_t padded = (plainLen + 15) & ~(size_t)15;

	uint8 scratch[2048];
	if (padded > sizeof(scratch))
		return 0;
	if (plainLen > 0)
		memcpy(scratch, plain, plainLen);
	memset(scratch + plainLen, 0, padded - plainLen);

	out[0] = 4;
	out[1] = out[2] = out[3] = 0;
	store32_le(out + 4, fReceiverIndex);
	store64_le(out + 8, fSendCounter);
	if (!wg::AeadEncrypt(fSendKey, fSendCounter, scratch, padded, NULL, 0,
			out + 16))
		return 0;
	fSendCounter++;
	return 16 + padded + 16;
}


ssize_t
WireGuardBackend::_Decapsulate(const uint8* packet, size_t packetLen,
	uint8* out)
{
	if (packetLen < 32 || packet[0] != 4)
		return -1;
	uint64 counter = load64_le(packet + 8);
	size_t cipherLen = packetLen - 16;		// ciphertext + 16-byte tag
	// TODO(wireguard): enforce the sliding replay window on `counter`.
	if (!wg::AeadDecrypt(fRecvKey, counter, packet + 16, cipherLen, NULL, 0,
			out))
		return -1;
	size_t plainLen = cipherLen - 16;		// still padded
	return (ssize_t)ip_packet_length(out, plainLen);
}


// One AllowedIPs entry, resolved to the network + dotted netmask the Haiku
// `route` command wants.
struct Cidr {
	BString	net;
	BString	mask;
	bool	isDefault;		// 0.0.0.0/0 -- the full-tunnel catch-all
};


// Parse "10.0.0.0/24, 0.0.0.0/0" into Cidr entries. IPv4 only for now; IPv6
// entries (containing ':') are skipped -- TODO(wireguard).
static std::vector<Cidr>
parse_allowed_ips(const BString& allowed)
{
	std::vector<Cidr> out;
	int32 start = 0;
	while (start <= allowed.Length()) {
		int32 comma = allowed.FindFirst(',', start);
		int32 end = (comma < 0) ? allowed.Length() : comma;
		BString token;
		allowed.CopyInto(token, start, end - start);
		token.Trim();
		start = end + 1;
		if (token.Length() == 0 || token.FindFirst(':') >= 0)
			continue;

		BString net = token;
		int prefix = 32;
		int32 slash = token.FindFirst('/');
		if (slash >= 0) {
			net.Truncate(slash);
			BString p;
			token.CopyInto(p, slash + 1, token.Length() - slash - 1);
			prefix = atoi(p.String());
		}
		net.Trim();
		if (net.Length() == 0 || prefix < 0 || prefix > 32)
			continue;

		uint32 m = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
		Cidr c;
		c.net = net;
		c.mask.SetToFormat("%u.%u.%u.%u", (m >> 24) & 0xFF, (m >> 16) & 0xFF,
			(m >> 8) & 0xFF, m & 0xFF);
		c.isDefault = (net == "0.0.0.0" && prefix == 0);
		out.push_back(c);
	}
	return out;
}


void
WireGuardBackend::_InstallRoutes()
{
	if (fRoutesInstalled)
		return;

	std::vector<Cidr> cidrs = parse_allowed_ips(fConfig.peer.allowedIPs);
	if (cidrs.empty()) {
		printf("[WireGuard] no AllowedIPs to route\n");
		return;
	}

	bool anyDefault = false;
	for (size_t i = 0; i < cidrs.size(); i++)
		anyDefault = anyDefault || cidrs[i].isDefault;

	// The endpoint pin and the full-tunnel default swap both need the carrier's
	// current gateway. Discovering it can fail (route-table parsing); a full
	// tunnel without it would loop our own UDP, so bail rather than break the
	// user's internet.
	fOrigGateway = "";
	fOrigGatewayIface = "";
	fReplacedDefault = false;
	if (!TunDevice::DefaultGateway(fOrigGateway, fOrigGatewayIface)
			&& anyDefault) {
		fprintf(stderr, "[WireGuard] no default gateway found; refusing to "
			"install a full-tunnel route (it would loop)\n");
		return;
	}

	// 1) Pin the endpoint to the carrier so our encrypted UDP doesn't try to
	// flow back through the tunnel it carries.
	if (fEndpointIP.Length() > 0 && fOrigGateway.Length() > 0) {
		const char* const pin[] = {
			"route", "add", fOrigGatewayIface.String(), "inet",
			fEndpointIP.String(), "gw", fOrigGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(pin);
	}

	// 2) For a full tunnel, drop the carrier default before adding ours.
	if (anyDefault && fOrigGateway.Length() > 0) {
		const char* const drop[] = {
			"route", "delete", fOrigGatewayIface.String(), "inet", "0.0.0.0",
			"gw", fOrigGateway.String(), "netmask", "0.0.0.0", NULL
		};
		TunDevice::RunRoute(drop);
		fReplacedDefault = true;
	}

	// 3) Route each AllowedIPs range into the tun, using the interface's own
	// address as the on-link next hop (the tun is point-to-point self).
	for (size_t i = 0; i < cidrs.size(); i++) {
		const char* const add[] = {
			"route", "add", fTunInterface.String(), "inet",
			cidrs[i].net.String(), "gw", fTunSelfIP.String(),
			"netmask", cidrs[i].mask.String(), NULL
		};
		TunDevice::RunRoute(add);
	}

	fRoutesInstalled = true;
}


void
WireGuardBackend::_RemoveRoutes()
{
	if (!fRoutesInstalled)
		return;

	std::vector<Cidr> cidrs = parse_allowed_ips(fConfig.peer.allowedIPs);
	for (size_t i = 0; i < cidrs.size(); i++) {
		const char* const del[] = {
			"route", "delete", fTunInterface.String(), "inet",
			cidrs[i].net.String(), "gw", fTunSelfIP.String(),
			"netmask", cidrs[i].mask.String(), NULL
		};
		TunDevice::RunRoute(del);
	}

	if (fReplacedDefault && fOrigGateway.Length() > 0) {
		const char* const restore[] = {
			"route", "add", fOrigGatewayIface.String(), "inet", "0.0.0.0",
			"gw", fOrigGateway.String(), "netmask", "0.0.0.0", NULL
		};
		TunDevice::RunRoute(restore);
	}
	if (fEndpointIP.Length() > 0 && fOrigGateway.Length() > 0) {
		const char* const unpin[] = {
			"route", "delete", fOrigGatewayIface.String(), "inet",
			fEndpointIP.String(), "gw", fOrigGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(unpin);
	}

	fRoutesInstalled = false;
	fReplacedDefault = false;
}


void
WireGuardBackend::_StartReader()
{
	fReader = spawn_thread(_ReaderEntry, "wireguard-reader",
		B_NORMAL_PRIORITY, this);
	if (fReader < B_OK) {
		fReader = -1;
		fprintf(stderr, "[WireGuard] spawn_thread failed\n");
		return;
	}
	resume_thread(fReader);
}


int32
WireGuardBackend::_ReaderEntry(void* self)
{
	return ((WireGuardBackend*)self)->_RunReaderLoop();
}


int32
WireGuardBackend::_RunReaderLoop()
{
	BMessenger self(this);

	// Handshake, retransmitting a few times if the response doesn't land.
	bool handshook = false;
	for (int i = 0; i < kHandshakeAttempts && !fStopRequested; i++) {
		if (_PerformHandshake()) {
			handshook = true;
			break;
		}
	}
	if (!handshook) {
		BMessage exited(kMsgWgReaderExited);
		exited.AddString("detail", fStopRequested ? "" : "handshake failed");
		self.SendMessage(&exited);
		return 0;
	}

	fSendCounter = 0;
	printf("[WireGuard] handshake OK (session %u <-> %u)\n",
		(unsigned)fSenderIndex, (unsigned)fReceiverIndex);
	self.SendMessage(kMsgWgConnected);

	// Non-blocking for the select() loop; the handshake used blocking recv.
	fcntl(fUdpSocket, F_SETFL, fcntl(fUdpSocket, F_GETFL, 0) | O_NONBLOCK);
	fcntl(fTunFd, F_SETFL, fcntl(fTunFd, F_GETFL, 0) | O_NONBLOCK);

	bigtime_t keepalive = fConfig.peer.persistentKeepalive > 0
		? (bigtime_t)fConfig.peer.persistentKeepalive * 1000000LL : 0;
	bigtime_t lastSend = system_time();
	bigtime_t lastStats = lastSend;
	uint64 bytesIn = 0;
	uint64 bytesOut = 0;

	uint8 plain[2048];
	uint8 wire[2048];

	while (!fStopRequested) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fTunFd, &rfds);
		FD_SET(fUdpSocket, &rfds);
		int maxfd = (fTunFd > fUdpSocket ? fTunFd : fUdpSocket) + 1;
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = kReaderPollInterval;
		int r = select(maxfd, &rfds, NULL, NULL, &tv);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		// Outbound: tun -> encrypt -> UDP. Cap the read so the encapsulated
		// packet fits `wire` comfortably.
		if (r > 0 && FD_ISSET(fTunFd, &rfds)) {
			ssize_t n = read(fTunFd, plain, 1500);
			if (n > 0) {
				size_t len = _Encapsulate(plain, (size_t)n, wire);
				if (len > 0 && send(fUdpSocket, wire, len, 0) == (ssize_t)len) {
					bytesOut += (uint64)n;
					lastSend = system_time();
				}
			}
		}

		// Inbound: UDP -> decrypt -> tun. plen == 0 is a keepalive (nothing to
		// write); plen < 0 is a non-data or failed packet (dropped).
		if (r > 0 && FD_ISSET(fUdpSocket, &rfds)) {
			ssize_t n = recv(fUdpSocket, wire, sizeof(wire), 0);
			if (n > 0) {
				ssize_t plen = _Decapsulate(wire, (size_t)n, plain);
				if (plen > 0) {
					write(fTunFd, plain, (size_t)plen);
					bytesIn += (uint64)plen;
				}
			}
		}

		bigtime_t now = system_time();
		if (keepalive > 0 && now - lastSend >= keepalive) {
			size_t len = _Encapsulate(NULL, 0, wire);
			if (len > 0)
				send(fUdpSocket, wire, len, 0);
			lastSend = now;
		}
		if (now - lastStats >= 1000000LL) {
			BMessage stats(kMsgWgStats);
			stats.AddInt64("in", (int64)bytesIn);
			stats.AddInt64("out", (int64)bytesOut);
			self.SendMessage(&stats);
			lastStats = now;
		}
	}

	BMessage exited(kMsgWgReaderExited);
	exited.AddString("detail", "");		// clean stop
	self.SendMessage(&exited);
	return 0;
}


void
WireGuardBackend::_Cleanup()
{
	// Stop the reader and join it before pulling the fds/interface out from
	// under it. Safe to call twice (fReader/fds are cleared as we go).
	fStopRequested = true;
	if (fReader > 0) {
		status_t exitCode = 0;
		wait_for_thread(fReader, &exitCode);
		fReader = -1;
	}

	// Drop our routes before the interface goes away, so the carrier default
	// is restored while its gateway is still reachable.
	_RemoveRoutes();

	delete fTimer;
	fTimer = NULL;

	if (fTunFd >= 0) {
		close(fTunFd);
		fTunFd = -1;
	}
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
