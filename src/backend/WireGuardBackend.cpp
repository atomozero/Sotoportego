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
#include <unistd.h>

#include <MessageRunner.h>

#include "TunDevice.h"
#include "VPNProfile.h"


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

	// TODO(wireguard): the handshake and data plane go here --
	//   if (!_PerformHandshake()) { _Cleanup(); _SetState(ERROR, ...); return B_ERROR; }
	//   _StartReader();  // + arm rekey / keepalive timers via fTimer
	//   return B_OK;     // CONNECTED is posted from the reader once keys are live
	//
	// Steps 1-2 are in place (keys decoded, tun up, UDP bound), but without
	// the Noise IK handshake we can't carry traffic, so tear the plumbing
	// back down and report clearly rather than leaving a half-open interface.
	_Cleanup();
	_SetState(VPN_STATE_ERROR, "WireGuard handshake not yet implemented");
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


bool
WireGuardBackend::_PerformHandshake()
{
	// TODO(wireguard): Noise IK handshake -- initiation + response, deriving
	// the transport keys (Curve25519 / BLAKE2s / ChaCha20-Poly1305 via
	// libsodium). Retransmit the initiation on fTimer until the response lands.
	return false;
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
