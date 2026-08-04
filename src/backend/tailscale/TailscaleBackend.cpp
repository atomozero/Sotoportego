/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TailscaleBackend.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <Messenger.h>

#include "VPNProfile.h"

#include "TSControl.h"			// kControlProtocolVersion
#include "TSControlSession.h"
#include "TSDisco.h"
#include "TSMap.h"
#include "TSRegister.h"
#include "TunDevice.h"
#include "WireGuardCrypto.h"		// RandomBytes


// Private messages the control worker posts back to the looper.
static const uint32 kMsgTsAuthURL		= 'tsAu';	// "url"
static const uint32 kMsgTsAuthorized	= 'tsOk';
static const uint32 kMsgTsFailed		= 'tsEr';	// "detail" (empty == stopped)
static const uint32 kMsgTsNetmap		= 'tsNm';	// "peers" int32, "selfip"
static const uint32 kMsgTsEndpoint		= 'tsEp';	// "endpoint" (public ip:port)

// Default coordination server when a profile doesn't name one.
static const char* const kDefaultControlHost = "controlplane.tailscale.com";


TailscaleBackend::TailscaleBackend()
	:
	VPNBackend("tailscale_backend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fLocalIP(""),
	fRemoteIP(""),
	fControlHost(""),
	fHostname(""),
	fAuthKey(""),
	fWorker(-1),
	fStopRequested(false),
	fTunFd(-1),
	fTunReader(-1),
	fSockReader(-1),
	fDerpReader(-1),
	fDnsFd(-1),
	fDnsThread(-1),
	fSessionLock("ts session"),
	fDerpUp(false)
{
}


TailscaleBackend::~TailscaleBackend()
{
	_StopWorker();
	_StopDataPlane();
	_TeardownTun();
}


status_t
TailscaleBackend::Connect(const VPNProfile& profile)
{
	if (profile.fName.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "Tailscale profile has no name");
		return B_BAD_VALUE;
	}
	if (fWorker >= 0) {
		_SetState(VPN_STATE_ERROR, "a Tailscale connection is already in flight");
		return B_NOT_ALLOWED;
	}

	// Phase 1: establish this node's persistent identity (machine/node/disco
	// keys), loaded from the keystore or minted and stored on first use.
	bool createdAny = false;
	status_t result = fIdentity.LoadOrCreate(profile.fName.String(),
		&createdAny);
	if (result != B_OK) {
		_SetState(VPN_STATE_ERROR, "could not establish node identity");
		return result;
	}
	BString nodePub = ts::TSIdentity::ToHex(fIdentity.NodePublic(), 32);
	printf("[tailscale] identity ready for '%s' (%s) node:%s\n",
		profile.fName.String(), createdAny ? "generated" : "reused",
		nodePub.String());

	// Snapshot what the worker needs so the thread never touches the profile.
	// fServer carries the control host for a Tailscale profile; default to the
	// public coordination server. The tailnet hostname defaults to the profile
	// name.
	if (profile.fServer.Length() > 0)
		fControlHost = profile.fServer;
	else
		fControlHost = kDefaultControlHost;
	fHostname = profile.fName;
	fAuthKey = "";	// TODO: read an optional pre-auth key from TSConfig

	fStopRequested = false;
	_SetState(VPN_STATE_CONNECTING);
	_StartWorker();
	if (fWorker < 0) {
		_SetState(VPN_STATE_ERROR, "could not start the Tailscale control worker");
		return B_ERROR;
	}
	return B_OK;
}


status_t
TailscaleBackend::Disconnect()
{
	// Ask the worker to stop; it posts kMsgTsFailed("") when it unwinds, which
	// settles the state on Disconnected. If no worker is running, drop straight
	// to Disconnected.
	fStopRequested = true;
	if (fWorker < 0)
		_SetState(VPN_STATE_DISCONNECTED);
	return B_OK;
}


VPNState
TailscaleBackend::State() const
{
	return fState;
}


VPNStats
TailscaleBackend::Stats() const
{
	return fStats;
}


const char*
TailscaleBackend::BackendName() const
{
	return "Tailscale";
}


BString
TailscaleBackend::LocalIP() const
{
	return fLocalIP;
}


BString
TailscaleBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
TailscaleBackend::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgTsAuthURL:
		{
			// Interactive login required: surface the URL so the GUI can show
			// (and open) it. Stay in AUTHENTICATING while we poll.
			const char* url = NULL;
			if (message->FindString("url", &url) == B_OK && url != NULL) {
				printf("[tailscale] auth required: %s\n", url);
				_SetState(VPN_STATE_AUTHENTICATING, url);
			}
			break;
		}

		case kMsgTsAuthorized:
			// Control authorized; the worker now long-polls the network map.
			printf("[tailscale] node authorized; fetching network map\n");
			_SetState(VPN_STATE_AUTHENTICATING, "authorized -- fetching network map");
			break;

		case kMsgTsNetmap:
		{
			// A MapResponse was applied. Report the netmap summary. The packet
			// data plane (magicsock reader + tun) isn't wired yet, so this is
			// not a full CONNECTED tunnel -- reflect that in the detail.
			int32 peers = 0;
			const char* selfip = NULL;
			message->FindInt32("peers", &peers);
			if (message->FindString("selfip", &selfip) == B_OK && selfip != NULL)
				fLocalIP = selfip;	// tun bring-up happens on the worker
			BString detail;
			detail.SetToFormat("netmap: %d peer%s%s%s (data plane pending)",
				(int)peers, peers == 1 ? "" : "s",
				(selfip && *selfip) ? ", self " : "",
				(selfip && *selfip) ? selfip : "");
			printf("[tailscale] %s\n", detail.String());
			_SetState(VPN_STATE_AUTHENTICATING, detail.String());
			break;
		}

		case kMsgTsEndpoint:
		{
			const char* ep = NULL;
			if (message->FindString("endpoint", &ep) == B_OK && ep != NULL) {
				fRemoteIP = ep;	// our reflexive endpoint (shown as the summary)
				printf("[tailscale] advertised endpoint: %s\n", ep);
			}
			break;
		}

		case kMsgTsFailed:
		{
			fWorker = -1;
			_StopDataPlane();
			_TeardownTun();
			const char* detail = NULL;
			if (message->FindString("detail", &detail) != B_OK)
				detail = NULL;
			if (detail == NULL || *detail == '\0')
				_SetState(VPN_STATE_DISCONNECTED);
			else
				_SetState(VPN_STATE_ERROR, detail);
			break;
		}

		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


void
TailscaleBackend::_StartWorker()
{
	fWorker = spawn_thread(_WorkerEntry, "tailscale-control",
		B_NORMAL_PRIORITY, this);
	if (fWorker < B_OK) {
		fWorker = -1;
		fprintf(stderr, "[tailscale] spawn_thread failed\n");
		return;
	}
	resume_thread(fWorker);
}


static uint32
le32(const uint8* p)
{
	return (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
}


// Resolve a peer's current send endpoint ("ip:port") into a sockaddr_in: the
// disco-upgraded direct path if we have one, else its first advertised
// endpoint. Returns false if the peer has no usable endpoint yet.
static bool
peer_sockaddr(ts::ManagedPeer* peer, struct sockaddr_in& out)
{
	BString ep;
	if (peer->path.Mode() == ts::PATH_DIRECT
			&& peer->path.DirectEndpoint().Length() > 0)
		ep = peer->path.DirectEndpoint();
	else if (!peer->endpoints.empty())
		ep = peer->endpoints[0];
	if (ep.Length() == 0)
		return false;

	int colon = ep.FindLast(':');
	if (colon < 0)
		return false;
	BString host(ep);
	host.Truncate(colon);
	int port = atoi(ep.String() + colon + 1);
	if (port <= 0)
		return false;

	memset(&out, 0, sizeof(out));
	out.sin_family = AF_INET;
	out.sin_port = htons((uint16)port);
	if (inet_pton(AF_INET, host.String(), &out.sin_addr) != 1)
		return false;	// IPv6 endpoints not handled on the underlay here
	return true;
}


// Send raw WireGuard bytes to a peer on its best available path: a direct UDP
// endpoint if one is known, otherwise relayed via DERP (keyed by node key).
// Caller holds fSessionLock.
void
TailscaleBackend::_SendPeerBytes(ts::ManagedPeer* peer, const uint8* buf,
	size_t len)
{
	struct sockaddr_in to;
	if (peer_sockaddr(peer, to)) {
		fMagicSock.SendTo((struct sockaddr*)&to, sizeof(to), buf, len);
	} else if (fDerpUp) {
		fDerp.SendPacket(peer->wg.NodeKey(), buf, len);
	}
}


void
TailscaleBackend::_SendToPeer(ts::ManagedPeer* peer, const uint8* packet,
	size_t len)
{
	if (!peer->wg.HasKeys()) {
		// Lazily start a WireGuard handshake, throttled so a burst of packets
		// doesn't flood initiations. The response arrives on a reader thread.
		bigtime_t now = system_time();
		if (now - peer->lastHandshake > 5000000) {
			uint8 init[148];
			if (peer->wg.BuildInitiation(fIdentity.NodePrivate(),
					peer->wg.NodeKey(), init) == 148) {
				peer->lastHandshake = now;
				_SendPeerBytes(peer, init, 148);
			}
		}
		return;	// drop this data packet until the session is up
	}

	uint8 out[2048];
	size_t n = peer->wg.Encapsulate(packet, len, out);
	if (n > 0)
		_SendPeerBytes(peer, out, n);

	// While relaying via DERP, probe the peer's endpoints so a direct path can
	// take over.
	if (peer->path.Mode() != ts::PATH_DIRECT)
		_SendDiscoPing(peer);
}


void
TailscaleBackend::_SendDiscoPing(ts::ManagedPeer* peer)
{
	if (peer->discoKey.Length() == 0 || peer->endpoints.empty())
		return;
	bigtime_t now = system_time();
	if (now - peer->lastDiscoPing < 2000000)	// throttle to ~0.5 Hz
		return;
	peer->lastDiscoPing = now;

	uint8 peerDisco[32];
	if (!ts::TSIdentity::FromHex(peer->discoKey.String(), peerDisco, 32))
		return;

	// A disco ping carries a random txid + our node key; a returning pong
	// arrives on whichever endpoint worked.
	uint8 txid[12];
	wg::RandomBytes(txid, 12);
	uint8 ping[64];
	size_t pl = ts::EncodePing(ping, txid, fIdentity.NodePublic());
	uint8 pkt[256];
	ssize_t pn = ts::DiscoSeal(pkt, sizeof(pkt), fIdentity.DiscoPublic(),
		fIdentity.DiscoPrivate(), peerDisco, ping, pl);
	if (pn < 0)
		return;

	// Send to every candidate endpoint.
	for (size_t i = 0; i < peer->endpoints.size(); i++) {
		int colon = peer->endpoints[i].FindLast(':');
		if (colon < 0)
			continue;
		BString host(peer->endpoints[i]);
		host.Truncate(colon);
		int port = atoi(peer->endpoints[i].String() + colon + 1);
		struct sockaddr_in to;
		memset(&to, 0, sizeof(to));
		to.sin_family = AF_INET;
		to.sin_port = htons((uint16)port);
		if (inet_pton(AF_INET, host.String(), &to.sin_addr) == 1)
			fMagicSock.SendTo((struct sockaddr*)&to, sizeof(to), pkt, pn);
	}
}


void
TailscaleBackend::_HandleDiscoPacket(const uint8* buf, size_t len,
	const struct sockaddr_in& from)
{
	uint8 sender[32];
	uint8 payload[128];
	ssize_t pl = ts::DiscoOpen(buf, len, fIdentity.DiscoPrivate(), sender,
		payload, sizeof(payload));
	if (pl < 0)
		return;

	char ip[16];
	inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
	uint16 port = ntohs(from.sin_port);
	uint8 type = ts::DiscoMessageType(payload, (size_t)pl);

	if (type == ts::DISCO_PING) {
		// Answer with a pong echoing the txid and the source we observed, so the
		// pinger learns this endpoint reaches us.
		ts::DiscoPing dp;
		if (!ts::DecodePing(payload, (size_t)pl, dp))
			return;
		uint8 pong[64];
		size_t pn = ts::EncodePong(pong, dp.txid, ip, port);
		uint8 pkt[256];
		ssize_t sn = ts::DiscoSeal(pkt, sizeof(pkt), fIdentity.DiscoPublic(),
			fIdentity.DiscoPrivate(), sender, pong, pn);
		if (sn > 0)
			fMagicSock.SendTo((struct sockaddr*)&from, sizeof(from), pkt, sn);
	} else if (type == ts::DISCO_PONG) {
		// A pong means the address it arrived from is a working direct path.
		BString senderHex = ts::TSIdentity::ToHex(sender, 32);
		BString endpoint;
		endpoint.SetToFormat("%s:%u", ip, (unsigned)port);
		fSessionLock.Lock();
		ts::ManagedPeer* p = fSession.Peers().FindByDiscoKey(senderHex.String());
		if (p != NULL) {
			p->path.UpgradeToDirect(endpoint.String(), system_time());
			printf("[tailscale] direct path to %s via %s\n",
				p->hostname.String(), endpoint.String());
		}
		fSessionLock.Unlock();
	}
}


void
TailscaleBackend::_HandleWireGuardPacket(const uint8* buf, size_t len)
{
	if (len < 4)
		return;
	if (buf[0] == 2 && len == 92) {
		// Handshake response: receiver index (bytes 8..11) is our sender idx.
		uint32 idx = le32(buf + 8);
		fSessionLock.Lock();
		ts::ManagedPeer* p = fSession.Peers().FindBySenderIndex(idx);
		if (p != NULL)
			p->wg.ConsumeResponse(buf, len);
		fSessionLock.Unlock();
	} else if (buf[0] == 4 && len >= 32) {
		// Transport data: receiver index (bytes 4..7) is our sender idx.
		uint32 idx = le32(buf + 4);
		uint8 out[2048];
		ssize_t plen = -1;
		fSessionLock.Lock();
		ts::ManagedPeer* p = fSession.Peers().FindBySenderIndex(idx);
		if (p != NULL)
			plen = p->wg.Decapsulate(buf, len, out);
		fSessionLock.Unlock();
		if (plen > 0 && fTunFd >= 0)
			write(fTunFd, out, (size_t)plen);	// deliver to the tun
	}
}


void
TailscaleBackend::_StartMagicDns()
{
	if (fDnsFd >= 0)
		return;
	BString selfIP = fSession.SelfIPv4();
	if (selfIP.Length() == 0)
		return;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	// Bind to our tailnet address so lookups aimed at this node's resolver land
	// here. (Tailscale's canonical 100.100.100.100 needs that alias on the tun;
	// binding our own 100.x is the portable choice on Haiku.)
	inet_pton(AF_INET, selfIP.String(), &addr.sin_addr);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		close(sock);
		fprintf(stderr, "[tailscale] MagicDNS bind %s:53 failed\n",
			selfIP.String());
		return;
	}
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	fDnsFd = sock;

	fDnsThread = spawn_thread(_DnsEntry, "tailscale-dns", B_NORMAL_PRIORITY,
		this);
	if (fDnsThread >= 0)
		resume_thread(fDnsThread);
	printf("[tailscale] MagicDNS resolver on %s:53\n", selfIP.String());
}


void
TailscaleBackend::_StopMagicDns()
{
	if (fDnsFd >= 0) {
		close(fDnsFd);
		fDnsFd = -1;
	}
	if (fDnsThread >= 0) {
		status_t ignored;
		wait_for_thread(fDnsThread, &ignored);
		fDnsThread = -1;
	}
}


int32
TailscaleBackend::_DnsEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunDnsServer();
}


int32
TailscaleBackend::_RunDnsServer()
{
	while (!fStopRequested) {
		uint8 query[1500];
		struct sockaddr_in from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(fDnsFd, query, sizeof(query), 0,
			(struct sockaddr*)&from, &fl);
		if (n <= 0)
			continue;	// timeout

		// Answer tailnet names locally; forward everything else upstream.
		uint8 resp[1500];
		ssize_t rn;
		fSessionLock.Lock();
		rn = fSession.Dns().Resolve(query, (size_t)n, resp, sizeof(resp));
		BString upstream;
		if (rn == 0 && !fSession.Netmap().Dns().resolvers.empty())
			upstream = fSession.Netmap().Dns().resolvers[0];
		fSessionLock.Unlock();

		if (rn > 0) {
			sendto(fDnsFd, resp, rn, 0, (struct sockaddr*)&from, fl);
			continue;
		}
		if (rn < 0 || upstream.Length() == 0)
			continue;	// malformed, or no upstream to forward to

		// Forward to the upstream resolver on a transient socket and relay the
		// reply back to the original client.
		int us = socket(AF_INET, SOCK_DGRAM, 0);
		if (us < 0)
			continue;
		struct timeval tv;
		tv.tv_sec = 4;
		tv.tv_usec = 0;
		setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		struct sockaddr_in up;
		memset(&up, 0, sizeof(up));
		up.sin_family = AF_INET;
		up.sin_port = htons(53);
		if (inet_pton(AF_INET, upstream.String(), &up.sin_addr) == 1
				&& sendto(us, query, n, 0, (struct sockaddr*)&up, sizeof(up))
					== n) {
			uint8 reply[1500];
			ssize_t rl = recv(us, reply, sizeof(reply), 0);
			if (rl > 0)
				sendto(fDnsFd, reply, rl, 0, (struct sockaddr*)&from, fl);
		}
		close(us);
	}
	return 0;
}


void
TailscaleBackend::_BringUpDerp()
{
	if (fDerpUp)
		return;
	// Use the first node of the first DERP region as our home relay.
	BString host;
	const std::vector<ts::DerpRegion>& regions = fSession.Netmap().DerpRegions();
	for (size_t i = 0; i < regions.size() && host.Length() == 0; i++) {
		if (!regions[i].nodes.empty())
			host = regions[i].nodes[0].hostName;
	}
	if (host.Length() == 0)
		return;
	if (fDerp.Connect(host.String(), 443, false, fIdentity.NodePrivate(),
			fIdentity.NodePublic()) != B_OK) {
		fprintf(stderr, "[tailscale] DERP connect to %s failed: %s\n",
			host.String(), fDerp.LastError());
		return;
	}
	fDerpUp = true;
	printf("[tailscale] DERP relay connected (%s)\n", host.String());
	fDerpReader = spawn_thread(_DerpReaderEntry, "tailscale-derp",
		B_NORMAL_PRIORITY, this);
	if (fDerpReader >= 0)
		resume_thread(fDerpReader);
}


int32
TailscaleBackend::_DerpReaderEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunDerpReader();
}


int32
TailscaleBackend::_RunDerpReader()
{
	uint8 src[32];
	uint8 buf[2048];
	while (!fStopRequested) {
		ssize_t n = fDerp.RecvPacket(src, buf, sizeof(buf));
		if (n < 0)
			break;		// relay connection dropped
		if (n == 0)
			continue;	// a control frame (keepalive/peer-gone/...)
		// A relayed packet is a raw WireGuard message; demux it like a direct
		// datagram (the receiver index identifies the session).
		_HandleWireGuardPacket(buf, (size_t)n);
	}
	return 0;
}


void
TailscaleBackend::_StartDataPlane()
{
	if (fTunFd >= 0)
		return;
	fTunFd = open(fTunNode.String(), O_RDWR | O_NONBLOCK);
	if (fTunFd < 0) {
		fprintf(stderr, "[tailscale] could not open %s\n", fTunNode.String());
		return;
	}
	fTunReader = spawn_thread(_TunReaderEntry, "tailscale-tun",
		B_NORMAL_PRIORITY, this);
	fSockReader = spawn_thread(_SockReaderEntry, "tailscale-magicsock",
		B_NORMAL_PRIORITY, this);
	if (fTunReader >= 0)
		resume_thread(fTunReader);
	if (fSockReader >= 0)
		resume_thread(fSockReader);
	printf("[tailscale] data plane started (tun %s)\n", fTunInterface.String());
}


void
TailscaleBackend::_StopDataPlane()
{
	fStopRequested = true;
	_StopMagicDns();
	// Closing the socket/tun unblocks the readers; they also poll the flag.
	if (fTunReader >= 0) {
		status_t ignored;
		wait_for_thread(fTunReader, &ignored);
		fTunReader = -1;
	}
	if (fSockReader >= 0) {
		status_t ignored;
		wait_for_thread(fSockReader, &ignored);
		fSockReader = -1;
	}
	if (fDerpUp) {
		fDerp.Close();	// unblocks the DERP reader's TLS read
		fDerpUp = false;
	}
	if (fDerpReader >= 0) {
		status_t ignored;
		wait_for_thread(fDerpReader, &ignored);
		fDerpReader = -1;
	}
	if (fTunFd >= 0) {
		close(fTunFd);
		fTunFd = -1;
	}
}


int32
TailscaleBackend::_TunReaderEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunTunReader();
}


int32
TailscaleBackend::_SockReaderEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunSockReader();
}


int32
TailscaleBackend::_RunTunReader()
{
	uint8 buf[2048];
	while (!fStopRequested) {
		fd_set rd;
		FD_ZERO(&rd);
		FD_SET(fTunFd, &rd);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 200000;	// 200ms so we notice a stop request
		int r = select(fTunFd + 1, &rd, NULL, NULL, &tv);
		if (r <= 0)
			continue;

		ssize_t n = read(fTunFd, buf, sizeof(buf));
		if (n < 20 || (buf[0] >> 4) != 4)
			continue;	// need a full IPv4 header (IPv6 not on the tun here)

		char dst[16];
		snprintf(dst, sizeof(dst), "%u.%u.%u.%u",
			buf[16], buf[17], buf[18], buf[19]);

		fSessionLock.Lock();
		ts::ManagedPeer* peer = fSession.Peers().FindByAllowedIP(dst);
		if (peer != NULL)
			_SendToPeer(peer, buf, (size_t)n);
		fSessionLock.Unlock();
	}
	return 0;
}


int32
TailscaleBackend::_RunSockReader()
{
	uint8 buf[2048];
	while (!fStopRequested) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		ssize_t n = fMagicSock.Recv(buf, sizeof(buf), &ss, &sl);
		if (n <= 0)
			continue;	// timeout / interrupted

		ts::SockPacketKind kind = ts::MagicSock::Classify(buf, (size_t)n);
		if (kind == ts::PKT_WIREGUARD) {
			_HandleWireGuardPacket(buf, (size_t)n);
		} else if (kind == ts::PKT_DISCO && ss.ss_family == AF_INET) {
			_HandleDiscoPacket(buf, (size_t)n,
				*(const struct sockaddr_in*)&ss);
		}
		// PKT_STUN here would be a late STUN reply; endpoint discovery already
		// ran during bring-up.
	}
	return 0;
}


void
TailscaleBackend::_BringUpTun(const char* selfIPv4)
{
	if (fTunInterface.Length() > 0 || selfIPv4 == NULL || *selfIPv4 == '\0')
		return;
	BString iface, node;
	if (!TunDevice::ProbeFreeSlot(iface, node)) {
		fprintf(stderr, "[tailscale] could not get a tun slot\n");
		return;
	}
	// Tailnet IPv4 lives in 100.64.0.0/10, so a /10 netmask (255.192.0.0)
	// makes all peer 100.x addresses on-link through the tun.
	const char* argv[] = { "ifconfig", iface.String(), "inet", selfIPv4,
		"netmask", "255.192.0.0", NULL };
	if (!TunDevice::RunIfconfig(argv)) {
		fprintf(stderr, "[tailscale] failed to assign %s to %s\n", selfIPv4,
			iface.String());
		return;
	}
	fTunInterface = iface;
	fTunNode = node;
	printf("[tailscale] tun %s up with %s/10\n", iface.String(), selfIPv4);
}


void
TailscaleBackend::_TeardownTun()
{
	if (fTunInterface.Length() == 0)
		return;
	const char* argv[] = { "ifconfig", fTunInterface.String(), "delete", NULL };
	TunDevice::RunIfconfig(argv, true);
	fTunInterface = "";
	fTunNode = "";
}


void
TailscaleBackend::_StopWorker()
{
	fStopRequested = true;
	if (fWorker >= 0) {
		status_t ignored;
		wait_for_thread(fWorker, &ignored);
		fWorker = -1;
	}
}


int32
TailscaleBackend::_WorkerEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunControlFlow();
}


int32
TailscaleBackend::_RunControlFlow()
{
	BMessenger self(this);
	uint16 version = ts::kControlProtocolVersion;

	ts::ControlSession session;
	ts::RegisterResult res;
	status_t result = session.Connect(fControlHost.String(), 443,
		false /* verify TLS */, version,
		fIdentity.MachinePrivate(), fIdentity.MachinePublic(),
		fIdentity.NodePublic(), fHostname.String(),
		fAuthKey.Length() > 0 ? fAuthKey.String() : NULL, res);

	if (fStopRequested) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", "");
		self.SendMessage(&m);
		return 0;
	}
	if (result != B_OK) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", session.LastError());
		self.SendMessage(&m);
		return 0;
	}
	if (res.error.Length() > 0) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", res.error.String());
		self.SendMessage(&m);
		return 0;
	}
	if (res.machineAuthorized) {
		self.SendMessage(kMsgTsAuthorized);
		_RunMap(session, self);
		return 0;
	}
	if (res.authURL.Length() == 0) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", "control returned neither authorization nor a "
			"login URL");
		self.SendMessage(&m);
		return 0;
	}

	// Interactive login: surface the URL and long-poll to authorized.
	{
		BMessage m(kMsgTsAuthURL);
		m.AddString("url", res.authURL.String());
		self.SendMessage(&m);
	}

	BString followup = res.authURL;
	while (!fStopRequested) {
		ts::RegisterResult pr;
		status_t pollResult = session.PollAuthorized(fControlHost.String(),
			version, fIdentity.NodePublic(), fHostname.String(),
			followup.String(), pr);
		if (fStopRequested)
			break;
		if (pollResult != B_OK) {
			BMessage m(kMsgTsFailed);
			m.AddString("detail", session.LastError());
			self.SendMessage(&m);
			return 0;
		}
		if (pr.error.Length() > 0) {
			BMessage m(kMsgTsFailed);
			m.AddString("detail", pr.error.String());
			self.SendMessage(&m);
			return 0;
		}
		if (pr.machineAuthorized) {
			self.SendMessage(kMsgTsAuthorized);
			_RunMap(session, self);
			return 0;
		}
		if (pr.authURL.Length() > 0)
			followup = pr.authURL;	// server may hand us a fresh followup URL
	}

	BMessage m(kMsgTsFailed);
	m.AddString("detail", "");	// stopped
	self.SendMessage(&m);
	return 0;
}


void
TailscaleBackend::_RunMap(ts::ControlSession& session, BMessenger& self)
{
	uint16 version = ts::kControlProtocolVersion;

	// The register/poll connections are closed by the server; open a fresh one
	// for the map long-poll.
	if (session.Establish() != B_OK) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", "could not open the network-map connection");
		self.SendMessage(&m);
		return;
	}

	ts::MapStream map;
	int status = 0;
	status_t result = map.Begin(session.Http2(), fControlHost.String(), version,
		fIdentity.NodePublic(), fHostname.String(), &status);
	if (result != B_OK || status != 200) {
		BMessage m(kMsgTsFailed);
		BString detail;
		detail.SetToFormat("network map request failed (HTTP %d)", status);
		m.AddString("detail", detail.String());
		self.SendMessage(&m);
		return;
	}

	// Stream MapResponses: the first is the full snapshot, then deltas. Apply
	// each to the session state and post a netmap summary.
	BString msg;
	while (!fStopRequested) {
		status_t r = map.ReadMessage(msg);
		if (r == B_ENTRY_NOT_FOUND)
			break;	// clean end of stream
		if (r != B_OK) {
			if (fStopRequested)
				break;
			// A read error (e.g. control drop) ends the map session.
			BMessage m(kMsgTsFailed);
			m.AddString("detail", "network map stream ended");
			self.SendMessage(&m);
			return;
		}
		fSessionLock.Lock();
		bool ok = fSession.ApplyMapResponse(msg.String(), msg.Length());
		fSessionLock.Unlock();
		if (!ok)
			continue;	// skip a malformed message, keep the stream

		// On the first netmap: open the data-plane UDP socket + learn our
		// endpoint (DERP STUN), bring up the tun with our tailnet address, and
		// start the packet reader threads.
		if (!fMagicSock.IsOpen()) {
			_BringUpMagicSock(self);
			BString selfip = fSession.SelfIPv4();
			if (fTunInterface.Length() == 0 && selfip.Length() > 0)
				_BringUpTun(selfip.String());
			if (fMagicSock.IsOpen() && fTunFd < 0 && fTunNode.Length() > 0)
				_StartDataPlane();
			_BringUpDerp();
			_StartMagicDns();
		}

		BMessage nm(kMsgTsNetmap);
		nm.AddInt32("peers", fSession.PeerCount());
		nm.AddString("selfip", fSession.SelfIPv4());
		self.SendMessage(&nm);
	}

	fMagicSock.Close();	// worker owns the socket; close it as the map loop ends

	BMessage done(kMsgTsFailed);
	done.AddString("detail", "");	// stopped
	self.SendMessage(&done);
}


void
TailscaleBackend::_BringUpMagicSock(BMessenger& self)
{
	if (fMagicSock.IsOpen())
		return;
	if (fMagicSock.Open(0) != B_OK) {
		fprintf(stderr, "[tailscale] magicsock open failed\n");
		return;
	}
	printf("[tailscale] magicsock on udp port %u\n",
		(unsigned)fMagicSock.LocalPort());

	// Pick a DERP node from the netmap to run STUN against (relays host the
	// STUN service on udp/3478).
	BString stunHost;
	const std::vector<ts::DerpRegion>& regions = fSession.Netmap().DerpRegions();
	for (size_t i = 0; i < regions.size() && stunHost.Length() == 0; i++) {
		if (!regions[i].nodes.empty())
			stunHost = regions[i].nodes[0].hostName;
	}
	if (stunHost.Length() == 0)
		return;

	BString ip;
	uint16 port = 0;
	if (fMagicSock.DiscoverEndpoint(stunHost.String(), 3478, ip, port) == B_OK) {
		BString endpoint;
		endpoint.SetToFormat("%s:%u", ip.String(), (unsigned)port);
		printf("[tailscale] public endpoint %s (via %s)\n",
			endpoint.String(), stunHost.String());
		BMessage m(kMsgTsEndpoint);
		m.AddString("endpoint", endpoint.String());
		self.SendMessage(&m);
	}
}


void
TailscaleBackend::RecoverIfCrashed()
{
	// Nothing to roll back yet: no tun slot, routes or resolv.conf are touched
	// until the data-plane phases land. Once they do, this mirrors
	// WireGuardBackend::RecoverIfCrashed() (tun/route/DNS teardown from a
	// recorded session file).
}


void
TailscaleBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	NotifyStateChanged(state, detail);
}
