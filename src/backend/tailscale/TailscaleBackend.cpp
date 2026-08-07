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
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <Messenger.h>

#include "VPNProfile.h"
#include "VPNProtocol.h"		// kFieldPeer* status fields

#include "TSBackoff.h"
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

// Resolve every IPv4 a host maps to (defined later; used by the exit-node
// carve-out planning, which appears earlier in the file).
static void resolve_all_ipv4(const char* host, std::vector<BString>& out);


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
	fExitDefaultReplaced(false),
	fTunFd(-1),
	fTunReader(-1),
	fSockReader(-1),
	fDerpReader(-1),
	fDnsFd(-1),
	fDnsThread(-1),
	fSessionLock("ts session"),
	fDerpLock("ts derp"),
	fDerpUp(false),
	fDerpHomeRegion(-1),
	fDerpHost(""),
	fLastDerpKeepalive(0)
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
	// Optional pre-auth key: when the profile carries one, register non-
	// interactively; otherwise fAuthKey stays empty and we fall back to the
	// browser SSO flow (register -> AuthURL -> followup poll).
	fAuthKey = profile.fAuthKey;

	// Fresh session: no exit node until the user (re)selects one.
	fSessionLock.Lock();
	fDesiredExitNode = "";
	fActiveExitNode = "";
	fSessionLock.Unlock();

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
TailscaleBackend::FillPeers(BMessage& out)
{
	// Called from the daemon looper while the worker mutates the session under
	// the same lock.
	fSessionLock.Lock();
	const std::vector<ts::ManagedPeer>& peers = fSession.Peers().Peers();
	for (size_t i = 0; i < peers.size(); i++) {
		const ts::ManagedPeer& p = peers[i];

		// The peer's tailnet IPv4 is its first IPv4 AllowedIP, with the /nn
		// prefix length stripped.
		BString ip;
		for (size_t j = 0; j < p.allowedIPs.size(); j++) {
			const BString& cidr = p.allowedIPs[j];
			if (cidr.FindFirst('.') < 0)
				continue;	// skip IPv6
			int slash = cidr.FindFirst('/');
			ip = (slash >= 0) ? BString(cidr.String(), slash) : cidr;
			break;
		}

		// Exit-node capability: a peer advertising 0.0.0.0/0 can be a full-tunnel
		// exit. Mark whether it's the one currently active, too.
		bool exitCap = false;
		for (size_t j = 0; j < p.allowedIPs.size(); j++) {
			if (p.allowedIPs[j] == "0.0.0.0/0") {
				exitCap = true;
				break;
			}
		}

		BMessage pm;
		pm.AddString(kFieldPeerName,
			p.hostname.Length() > 0 ? p.hostname.String() : "(unknown)");
		pm.AddString(kFieldPeerIP, ip);
		pm.AddBool(kFieldPeerOnline, p.online);
		pm.AddString(kFieldPeerPath,
			p.path.Mode() == ts::PATH_DIRECT ? "direct" : "relay");
		pm.AddString(kFieldPeerNodeKey, p.nodeKeyHex);
		pm.AddBool(kFieldPeerExitCap, exitCap);
		pm.AddBool(kFieldPeerExitOn, fActiveExitNode.Length() > 0
			&& fActiveExitNode == p.nodeKeyHex);
		out.AddMessage(kFieldPeer, &pm);
	}
	fSessionLock.Unlock();
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
			// A MapResponse was applied and the worker has attempted to bring up
			// the data plane. Once the tun is up we're a fully connected node on
			// the tailnet; until then we're still assembling the tunnel.
			int32 peers = 0;
			const char* selfip = NULL;
			bool up = false;
			message->FindInt32("peers", &peers);
			message->FindBool("up", &up);
			if (message->FindString("selfip", &selfip) == B_OK && selfip != NULL)
				fLocalIP = selfip;	// tun bring-up happens on the worker

			if (up) {
				BString detail;
				detail.SetToFormat("%s%s%d peer%s",
					(selfip && *selfip) ? selfip : "",
					(selfip && *selfip) ? " \xc2\xb7 " : "",
					(int)peers, peers == 1 ? "" : "s");
				printf("[tailscale] connected: %s\n", detail.String());
				_SetState(VPN_STATE_CONNECTED, detail.String());
			} else {
				BString detail;
				detail.SetToFormat("netmap: %d peer%s%s%s \xe2\x80\x94 bringing up "
					"tunnel", (int)peers, peers == 1 ? "" : "s",
					(selfip && *selfip) ? ", self " : "",
					(selfip && *selfip) ? selfip : "");
				printf("[tailscale] %s\n", detail.String());
				_SetState(VPN_STATE_AUTHENTICATING, detail.String());
			}
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
	// Only hand back a direct destination once disco has CONFIRMED it works;
	// until then the caller relays via DERP. The peer's advertised endpoints
	// are unverified and frequently unreachable -- e.g. a public address that
	// would need NAT hairpinning when both nodes sit behind the same router --
	// so sending real WireGuard traffic straight to endpoints[0] just black-
	// holed the handshake. Disco ping/pong is what promotes the path.
	if (peer->path.Mode() != ts::PATH_DIRECT
			|| peer->path.DirectEndpoint().Length() == 0)
		return false;
	BString ep = peer->path.DirectEndpoint();

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
		// Take fDerpLock so the reader can't Close+reconnect the relay out from
		// under this send; re-check fDerpUp inside in case it just went down.
		fDerpLock.Lock();
		if (fDerpUp)
			fDerp.SendPacket(peer->wg.NodeKey(), buf, len);
		fDerpLock.Unlock();
	}
}


void
TailscaleBackend::_SendToPeer(ts::ManagedPeer* peer, const uint8* packet,
	size_t len)
{
	// Probe for a direct path whenever we're still relaying -- BEFORE the
	// handshake check. Otherwise the disco pings were gated behind a completed
	// WireGuard session that itself never completes for a peer we can only
	// reach direct (same-NAT hole punch), so the path stayed stuck on DERP.
	if (peer->path.Mode() != ts::PATH_DIRECT)
		_SendDiscoPing(peer);

	bigtime_t now = system_time();
	// A session that aged past REJECT_AFTER_TIME (no rekey response ever came
	// back) is unusable -- drop the keys so the block below starts a fresh
	// handshake rather than encrypting with a key the peer now rejects.
	peer->wg.ExpireIfStale(now);

	if (!peer->wg.HasKeys()) {
		// Lazily start a WireGuard handshake, throttled so a burst of packets
		// doesn't flood initiations. The initiation goes via DERP (or a
		// confirmed direct path); the response arrives on a reader thread.
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

	// Live session: if it has aged past REKEY_AFTER_TIME, initiate a fresh
	// handshake now while still using the current keys (make-before-break) -- the
	// new keys install atomically when the response arrives.
	if (peer->wg.ShouldInitiateRekey(now)) {
		uint8 init[148];
		if (peer->wg.BuildInitiation(fIdentity.NodePrivate(),
				peer->wg.NodeKey(), init) == 148) {
			peer->lastHandshake = now;
			_SendPeerBytes(peer, init, 148);
		}
	}

	// Encapsulation adds up to 16 (header) + 15 (pad) + 16 (tag) over the payload;
	// size the buffer for a full tun read (2048) so a large packet can never
	// overflow it even if the tun MTU is raised.
	uint8 out[2048 + 64];
	size_t n = peer->wg.Encapsulate(packet, len, out);
	if (n > 0)
		_SendPeerBytes(peer, out, n);
}


// Periodic upkeep across all peers, driven off the tun reader's ~1s tick so it
// runs even when the tun is idle (an inbound-only session must still be rekeyed
// and kept warm). Caller must NOT hold fSessionLock; we take it here.
void
TailscaleBackend::_MaintainPeers()
{
	bigtime_t now = system_time();
	fSessionLock.Lock();
	size_t count = fSession.Peers().Count();
	for (size_t i = 0; i < count; i++) {
		ts::ManagedPeer* p = fSession.Peers().PeerAt(i);
		if (p == NULL || !p->wg.HasKeys())
			continue;
		if (p->wg.ExpireIfStale(now))
			continue;	// keys dropped; next outbound packet re-handshakes
		if (p->wg.ShouldInitiateRekey(now)) {
			uint8 init[148];
			if (p->wg.BuildInitiation(fIdentity.NodePrivate(),
					p->wg.NodeKey(), init) == 148) {
				p->lastHandshake = now;
				printf("[tailscale] rekeying WireGuard session with %s (age %ds)\n",
					p->hostname.String(), p->wg.SessionAgeSeconds(now));
				_SendPeerBytes(p, init, 148);
			}
		} else if (p->wg.ShouldKeepalive(now)) {
			uint8 out[64];
			size_t n = p->wg.Encapsulate(NULL, 0, out);	// empty keepalive
			if (n > 0)
				_SendPeerBytes(p, out, n);
		}
	}
	fSessionLock.Unlock();
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
	if (buf[0] == 1 && len == 148) {
		// Handshake initiation FROM a peer: the peer is (re)keying towards us, so
		// we take the responder role. Recover which peer it is (the encrypted
		// static decrypts to their node key), complete the responder handshake and
		// send the type-2 response back on the same path. Without this a peer that
		// rekeys first -- WireGuard rekeys every ~2 min -- would tear the session
		// down when we ignored its initiation.
		uint8 peerStatic[32];
		if (!ts::WGPeer::RecoverInitiatorStatic(fIdentity.NodePrivate(), buf, len,
				peerStatic))
			return;
		BString hex = ts::TSIdentity::ToHex(peerStatic, 32);
		fSessionLock.Lock();
		ts::ManagedPeer* p = fSession.Peers().Find(hex.String());
		if (p != NULL
				&& p->wg.ConsumeInitiation(fIdentity.NodePrivate(), buf, len)) {
			uint8 resp[92];
			if (p->wg.BuildResponse(resp) == 92) {
				_SendPeerBytes(p, resp, 92);
				printf("[tailscale] answered WireGuard rekey from %s\n",
					p->hostname.String());
			}
		}
		fSessionLock.Unlock();
	} else if (buf[0] == 2 && len == 92) {
		// Handshake response: receiver index (bytes 8..11) is our sender idx.
		uint32 idx = le32(buf + 8);
		fSessionLock.Lock();
		ts::ManagedPeer* p = fSession.Peers().FindBySenderIndex(idx);
		if (p != NULL) {
			p->wg.ConsumeResponse(buf, len);
			if (p->wg.HasKeys())
				printf("[tailscale] WireGuard session up with %s\n",
					p->hostname.String());
		}
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
	const ts::TSNetmap& nm = fSession.Netmap();
	const std::vector<ts::DerpRegion>& regions = nm.DerpRegions();

	// To relay to a peer over DERP you must connect to the region that peer is
	// homed on -- a DERP server only delivers to keys connected to it (regions
	// don't cross-forward). Pick the first peer's home region; both ends then
	// meet on the same relay. Fall back to the first region if unknown.
	int wantRegion = -1;
	const std::vector<ts::ManagedPeer>& peers = fSession.Peers().Peers();
	for (size_t i = 0; i < peers.size(); i++) {
		if (peers[i].derpRegion > 0) {
			wantRegion = peers[i].derpRegion;
			break;
		}
	}

	BString host;
	int chosen = -1;
	if (wantRegion > 0) {
		const ts::DerpRegion* r = nm.DerpRegionById(wantRegion);
		if (r != NULL && !r->nodes.empty()) {
			host = r->nodes[0].hostName;
			chosen = wantRegion;
		}
	}
	for (size_t i = 0; i < regions.size() && host.Length() == 0; i++) {
		if (!regions[i].nodes.empty()) {
			host = regions[i].nodes[0].hostName;
			chosen = regions[i].regionID;
		}
	}
	if (host.Length() == 0)
		return;
	if (fDerp.Connect(host.String(), 443, false, fIdentity.NodePrivate(),
			fIdentity.NodePublic()) != B_OK) {
		fprintf(stderr, "[tailscale] DERP connect to %s failed: %s\n",
			host.String(), fDerp.LastError());
		return;
	}
	fDerpLock.Lock();
	fDerpUp = true;
	fDerpLock.Unlock();
	fDerpHomeRegion = chosen;
	fDerpHost = host;					// remembered so the reader can reconnect
	fDerp.SetStopFlag(&fStopRequested);	// let the reader break out on stop
	printf("[tailscale] DERP relay connected (%s)\n", host.String());
	fDerpReader = spawn_thread(_DerpReaderEntry, "tailscale-derp",
		B_NORMAL_PRIORITY, this);
	if (fDerpReader >= 0)
		resume_thread(fDerpReader);
}


void
TailscaleBackend::_AdvertiseDerpHome(const char* lanEndpoint)
{
	// Endpoints = [ <lan, if any>, "127.3.3.40:<region>" ]. The 127.3.3.40:N
	// form is Tailscale's magic encoding for "reachable via DERP region N";
	// advertising it gives peers a return path to us over the relay.
	BString eps;
	if (lanEndpoint != NULL && *lanEndpoint != '\0') {
		eps << lanEndpoint;
		eps << ",";
	}
	eps << "\"127.3.3.40:" << fDerpHomeRegion << "\"";

	uint16 version = ts::kControlProtocolVersion;
	ts::ControlSession sess;
	sess.SetParams(fControlHost.String(), 443, false, version,
		fIdentity.MachinePrivate(), fIdentity.MachinePublic());
	if (sess.Establish() != B_OK)
		return;

	ts::MapStream m;
	int status = 0;
	status_t r = m.Begin(sess.Http2(), fControlHost.String(), version,
		fIdentity.NodePublic(), fIdentity.DiscoPublic(), fHostname.String(),
		eps.String(), false /* one-shot, not streamed */, &status);
	if (r != B_OK || status != 200) {
		printf("[tailscale] DERP-home advertise failed (HTTP %d)\n", status);
		return;
	}
	// Read and discard the single MapResponse so control fully processes the
	// updated endpoints before the connection closes.
	BString msg;
	m.ReadMessage(msg);
	printf("[tailscale] advertised DERP home region %d\n", fDerpHomeRegion);
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
	ts::ReconnectBackoff backoff(1000000LL /* 1s */, 30000000LL /* 30s */,
		30000000LL /* healthy >= 30s */);
	bigtime_t connectedAt = system_time();
	while (!fStopRequested) {
		ssize_t n = fDerp.RecvPacket(src, buf, sizeof(buf));
		if (n > 0) {
			// A relayed packet is a raw WireGuard message; demux it like a direct
			// datagram (the receiver index identifies the session).
			_HandleWireGuardPacket(buf, (size_t)n);
			continue;
		}
		if (n == 0)
			continue;	// a control frame (keepalive/peer-gone/...)

		// n < 0: the relay dropped (or a stop was requested). DERP is often the
		// only path to a peer, so a drop must not silently kill connectivity --
		// keep the rest of the data plane up and reconnect to the same home
		// region with backoff.
		if (fStopRequested)
			break;
		bigtime_t lasted = system_time() - connectedAt;
		printf("[tailscale] DERP relay dropped (up %llds) -- reconnecting\n",
			(long long)(lasted / 1000000));
		_DerpMarkDown();
		bigtime_t delay = backoff.NextDelay(true /* was connected */, lasted);
		if (!_SleepInterruptible(delay))
			break;
		if (_DerpReconnect())
			connectedAt = system_time();
	}
	return 0;
}


// Take the relay down after a drop: flip the flag so senders stop using it, then
// free the TLS session. Guarded by fDerpLock against a concurrent send.
void
TailscaleBackend::_DerpMarkDown()
{
	fDerpLock.Lock();
	fDerpUp = false;
	fDerp.Close();
	fDerpLock.Unlock();
}


// Reconnect to the remembered home-region DERP server. Guarded by fDerpLock so a
// sender never touches a half-open session. Returns true once the relay is back.
bool
TailscaleBackend::_DerpReconnect()
{
	if (fDerpHost.Length() == 0)
		return false;
	fDerpLock.Lock();
	status_t r = fDerp.Connect(fDerpHost.String(), 443, false,
		fIdentity.NodePrivate(), fIdentity.NodePublic());
	bool ok = (r == B_OK);
	if (ok) {
		fDerp.SetStopFlag(&fStopRequested);
		fDerpUp = true;
	}
	fDerpLock.Unlock();
	if (ok)
		printf("[tailscale] DERP relay reconnected (%s)\n", fDerpHost.String());
	else
		fprintf(stderr, "[tailscale] DERP reconnect to %s failed: %s\n",
			fDerpHost.String(), fDerp.LastError());
	return ok;
}


// Send a DERP client keepalive if the relay has been idle for a while, so a
// stateful firewall doesn't reap the flow when no packets are being relayed.
// Called from the tun reader's tick (NOT under fSessionLock).
void
TailscaleBackend::_DerpKeepaliveTick(bigtime_t now)
{
	if (now - fLastDerpKeepalive < 60000000)	// 60s
		return;
	fLastDerpKeepalive = now;
	fDerpLock.Lock();
	if (fDerpUp)
		fDerp.WriteFrame(ts::DERP_KEEP_ALIVE, NULL, 0);
	fDerpLock.Unlock();
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
	// The DERP reader breaks out of its idle read via the stop flag (set above)
	// within one receive timeout, so just JOIN it, THEN free the SSL. We must
	// NOT socket-shutdown to hurry it: on Haiku that wedges the pending recv
	// instead of waking it, and freeing the SSL while the reader is still inside
	// SSL_read is a use-after-free crash -- the join is what makes Close() safe.
	if (fDerpReader >= 0) {
		status_t ignored;
		wait_for_thread(fDerpReader, &ignored);
		fDerpReader = -1;
	}
	// The reader has exited (no concurrency now), but take fDerpLock anyway for
	// consistency with the reconnect path. If the reader tore the session down
	// during a reconnect, fDerpUp is already false and Close() is a no-op.
	fDerpLock.Lock();
	if (fDerpUp) {
		fDerp.Close();
		fDerpUp = false;
	}
	fDerpLock.Unlock();
	fDerpHost = "";
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
	bigtime_t lastMaint = 0;
	while (!fStopRequested) {
		fd_set rd;
		FD_ZERO(&rd);
		FD_SET(fTunFd, &rd);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 200000;	// 200ms so we notice a stop request
		int r = select(fTunFd + 1, &rd, NULL, NULL, &tv);

		// Run per-peer rekey/keepalive upkeep about once a second, on this same
		// thread, whether or not the tun had a packet -- an idle or inbound-only
		// session must still be rekeyed before REJECT_AFTER_TIME kills it.
		bigtime_t now = system_time();
		if (now - lastMaint >= 1000000) {
			_MaintainPeers();
			_DerpKeepaliveTick(now);
			_SyncExitNode();
			lastMaint = now;
		}

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
	// Cap the tunnel MTU to 1280 (Tailscale's standard). A full 1500-ish tun
	// packet plus WireGuard's 32-byte overhead exceeds the carrier's 1500 MTU
	// and gets fragmented or dropped, silently breaking large transfers (small
	// packets like pings still work, which masks it). 1280 leaves headroom for
	// the WireGuard + outer IP/UDP headers on any common underlay.
	const char* mtu[] = { "ifconfig", iface.String(), "mtu", "1280", NULL };
	TunDevice::RunIfconfig(mtu);	// best-effort
	fTunInterface = iface;
	fTunNode = node;
	fTunSelfIP = selfIPv4;	// on-link next hop for subnet routes
	printf("[tailscale] tun %s up with %s/10\n", iface.String(), selfIPv4);
}


// Reconcile the system routes for peer subnet routers against the current
// netmap: add a route onto the tun for every non-tailnet CIDR a peer advertises,
// and remove routes for CIDRs that are no longer advertised. Runs on the worker
// after each netmap; the peer-set demux then forwards the packets the kernel
// delivers to the tun. The default route (exit node) is not auto-installed.
void
TailscaleBackend::_SyncRoutes()
{
	if (fTunInterface.Length() == 0 || fTunSelfIP.Length() == 0)
		return;

	// Snapshot the peers' AllowedIPs under the lock; plan/execute without it.
	std::vector<BString> allowed;
	fSessionLock.Lock();
	size_t count = fSession.Peers().Count();
	for (size_t i = 0; i < count; i++) {
		ts::ManagedPeer* p = fSession.Peers().PeerAt(i);
		if (p == NULL)
			continue;
		for (size_t j = 0; j < p->allowedIPs.size(); j++)
			allowed.push_back(p->allowedIPs[j]);
	}
	fSessionLock.Unlock();

	std::vector<ts::SubnetRoute> desired;
	ts::ComputeSubnetRoutes(allowed, desired);

	std::vector<ts::SubnetRoute> toAdd, toRemove;
	fSessionLock.Lock();
	ts::DiffRoutes(desired, fInstalledRoutes, toAdd, toRemove);
	fInstalledRoutes = desired;
	fSessionLock.Unlock();

	for (size_t i = 0; i < toAdd.size(); i++) {
		const char* const add[] = {
			"route", "add", fTunInterface.String(), "inet",
			toAdd[i].net.String(), "gw", fTunSelfIP.String(),
			"netmask", toAdd[i].mask.String(), NULL
		};
		TunDevice::RunRoute(add);
		printf("[tailscale] + subnet route %s netmask %s via %s\n",
			toAdd[i].net.String(), toAdd[i].mask.String(),
			fTunInterface.String());
	}
	for (size_t i = 0; i < toRemove.size(); i++) {
		const char* const del[] = {
			"route", "delete", fTunInterface.String(), "inet",
			toRemove[i].net.String(), "gw", fTunSelfIP.String(),
			"netmask", toRemove[i].mask.String(), NULL
		};
		TunDevice::RunRoute(del);
		printf("[tailscale] - subnet route %s\n", toRemove[i].net.String());
	}
}


void
TailscaleBackend::_TeardownRoutes()
{
	std::vector<ts::SubnetRoute> routes;
	fSessionLock.Lock();
	routes.swap(fInstalledRoutes);
	fSessionLock.Unlock();
	for (size_t i = 0; i < routes.size(); i++) {
		const char* const del[] = {
			"route", "delete", fTunInterface.String(), "inet",
			routes[i].net.String(), "gw", fTunSelfIP.String(),
			"netmask", routes[i].mask.String(), NULL
		};
		TunDevice::RunRoute(del);
	}
}


status_t
TailscaleBackend::SetExitNode(const BString& id)
{
	// Record the request; the tun reader's tick applies it (route changes belong
	// on the data-plane thread, not the looper that called this).
	fSessionLock.Lock();
	fDesiredExitNode = id;
	fSessionLock.Unlock();
	printf("[tailscale] exit node requested: %s\n",
		id.Length() > 0 ? id.String() : "(none)");
	return B_OK;
}


void
TailscaleBackend::_ExitUnderlayIPs(const char* nodeKeyHex,
	std::vector<BString>& out)
{
	// Our own underlay endpoints that must keep leaving on the carrier: the
	// control server and the DERP relay we ride, plus the exit node's reachable
	// addresses (its candidate endpoints and any confirmed direct path).
	resolve_all_ipv4(fControlHost.String(), out);
	if (fDerpHost.Length() > 0)
		resolve_all_ipv4(fDerpHost.String(), out);

	fSessionLock.Lock();
	ts::ManagedPeer* p = fSession.Peers().Find(nodeKeyHex);
	if (p != NULL) {
		for (size_t i = 0; i < p->endpoints.size(); i++) {
			int colon = p->endpoints[i].FindLast(':');
			BString ip = (colon > 0)
				? BString(p->endpoints[i].String(), colon) : p->endpoints[i];
			if (ip.Length() > 0)
				out.push_back(ip);
		}
		if (p->path.Mode() == ts::PATH_DIRECT
				&& p->path.DirectEndpoint().Length() > 0) {
			const BString& ep = p->path.DirectEndpoint();
			int colon = ep.FindLast(':');
			BString ip = (colon > 0) ? BString(ep.String(), colon) : ep;
			if (ip.Length() > 0)
				out.push_back(ip);
		}
	}
	fSessionLock.Unlock();
}


void
TailscaleBackend::_EnableExitNode(const char* nodeKeyHex)
{
	// The tun must be up (it's the default route's next hop) and the peer must
	// actually advertise 0.0.0.0/0 (be exit-capable).
	if (fTunInterface.Length() == 0 || fTunSelfIP.Length() == 0)
		return;	// data plane not ready yet; the tick retries
	bool capable = false;
	fSessionLock.Lock();
	ts::ManagedPeer* p = fSession.Peers().Find(nodeKeyHex);
	if (p != NULL) {
		for (size_t i = 0; i < p->allowedIPs.size(); i++) {
			if (p->allowedIPs[i] == "0.0.0.0/0") {
				capable = true;
				break;
			}
		}
	}
	fSessionLock.Unlock();
	if (!capable) {
		fprintf(stderr, "[tailscale] exit node %s not found or not advertising "
			"0.0.0.0/0\n", nodeKeyHex);
		return;
	}

	BString gw, iface;
	if (!TunDevice::DefaultGateway(gw, iface)) {
		fprintf(stderr, "[tailscale] no default gateway; refusing exit-node full "
			"tunnel (it would loop)\n");
		return;
	}

	// Pin the underlay carve-outs to the carrier BEFORE capturing the default,
	// so control/DERP/exit-node traffic never routes into the tunnel it carries.
	std::vector<BString> underlay;
	_ExitUnderlayIPs(nodeKeyHex, underlay);
	std::vector<BString> carve;
	ts::ComputeExitCarveouts(underlay, carve);
	for (size_t i = 0; i < carve.size(); i++) {
		const char* const pin[] = {
			"route", "add", iface.String(), "inet", carve[i].String(),
			"gw", gw.String(), "netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(pin);
	}

	// Swap the default route onto the tun (all non-carve-out traffic now exits
	// through the peer, which advertises 0.0.0.0/0 and is picked by the demux).
	const char* const drop[] = {
		"route", "delete", iface.String(), "inet", "0.0.0.0",
		"gw", gw.String(), "netmask", "0.0.0.0", NULL
	};
	TunDevice::RunRoute(drop);
	const char* const add[] = {
		"route", "add", fTunInterface.String(), "inet", "0.0.0.0",
		"gw", fTunSelfIP.String(), "netmask", "0.0.0.0", NULL
	};
	TunDevice::RunRoute(add);

	fExitOrigGateway = gw;
	fExitOrigGatewayIface = iface;
	fExitDefaultReplaced = true;
	fExitCarveouts = carve;
	fSessionLock.Lock();		// FillPeers (looper thread) reads fActiveExitNode
	fActiveExitNode = nodeKeyHex;
	fSessionLock.Unlock();
	printf("[tailscale] exit node enabled: %s (%u carve-outs, default via %s)\n",
		nodeKeyHex, (unsigned)carve.size(), fTunInterface.String());
}


void
TailscaleBackend::_DisableExitNode()
{
	if (fActiveExitNode.Length() == 0)
		return;
	if (fExitDefaultReplaced) {
		const char* const drop[] = {
			"route", "delete", fTunInterface.String(), "inet", "0.0.0.0",
			"gw", fTunSelfIP.String(), "netmask", "0.0.0.0", NULL
		};
		TunDevice::RunRoute(drop);
		if (fExitOrigGateway.Length() > 0) {
			const char* const restore[] = {
				"route", "add", fExitOrigGatewayIface.String(), "inet",
				"0.0.0.0", "gw", fExitOrigGateway.String(),
				"netmask", "0.0.0.0", NULL
			};
			TunDevice::RunRoute(restore);
		}
	}
	for (size_t i = 0; i < fExitCarveouts.size(); i++) {
		const char* const unpin[] = {
			"route", "delete", fExitOrigGatewayIface.String(), "inet",
			fExitCarveouts[i].String(), "gw", fExitOrigGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(unpin);
	}
	printf("[tailscale] exit node disabled (%s)\n", fActiveExitNode.String());
	fExitCarveouts.clear();
	fExitOrigGateway = "";
	fExitOrigGatewayIface = "";
	fExitDefaultReplaced = false;
	fSessionLock.Lock();		// FillPeers (looper thread) reads fActiveExitNode
	fActiveExitNode = "";
	fSessionLock.Unlock();
}


void
TailscaleBackend::_ReconcileExitCarveouts()
{
	// The exit node's path can upgrade from relay to direct (or its endpoints can
	// change) after we enabled it: re-pin any newly-needed underlay address and
	// drop stale ones, WITHOUT touching the default route.
	if (fActiveExitNode.Length() == 0 || fExitOrigGateway.Length() == 0)
		return;
	std::vector<BString> underlay;
	_ExitUnderlayIPs(fActiveExitNode.String(), underlay);
	std::vector<BString> desired;
	ts::ComputeExitCarveouts(underlay, desired);
	std::vector<BString> toAdd, toRemove;
	ts::DiffCarveouts(desired, fExitCarveouts, toAdd, toRemove);
	if (toAdd.empty() && toRemove.empty())
		return;
	for (size_t i = 0; i < toAdd.size(); i++) {
		const char* const pin[] = {
			"route", "add", fExitOrigGatewayIface.String(), "inet",
			toAdd[i].String(), "gw", fExitOrigGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(pin);
		printf("[tailscale] exit carve-out + %s\n", toAdd[i].String());
	}
	for (size_t i = 0; i < toRemove.size(); i++) {
		const char* const unpin[] = {
			"route", "delete", fExitOrigGatewayIface.String(), "inet",
			toRemove[i].String(), "gw", fExitOrigGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		TunDevice::RunRoute(unpin);
	}
	fExitCarveouts = desired;
}


void
TailscaleBackend::_SyncExitNode()
{
	fSessionLock.Lock();
	BString desired = fDesiredExitNode;
	fSessionLock.Unlock();

	if (desired != fActiveExitNode) {
		if (fActiveExitNode.Length() > 0)
			_DisableExitNode();
		if (desired.Length() > 0)
			_EnableExitNode(desired.String());
	} else if (fActiveExitNode.Length() > 0) {
		_ReconcileExitCarveouts();
	}
}


void
TailscaleBackend::_TeardownTun()
{
	if (fTunInterface.Length() == 0)
		return;
	// Restore the default route (if an exit node captured it) and drop our subnet
	// routes before the interface -- their next hop -- goes away.
	_DisableExitNode();
	_TeardownRoutes();
	// Haiku's ifconfig removes an interface with "--delete <iface>", not
	// "<iface> delete" (which just prints a usage error).
	const char* argv[] = { "ifconfig", "--delete", fTunInterface.String(),
		NULL };
	TunDevice::RunIfconfig(argv, true);
	fTunInterface = "";
	fTunNode = "";
	fTunSelfIP = "";
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


// Learn our primary LAN IPv4 by asking the kernel which source address it
// would use to reach `host`. No packet is sent (UDP connect just sets the
// route); getsockname then reports the chosen local address.
static BString
local_ipv4(const char* host)
{
	BString result;
	struct addrinfo hints;
	struct addrinfo* ai = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, "443", &hints, &ai) != 0 || ai == NULL)
		return result;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
			struct sockaddr_in local;
			socklen_t ll = sizeof(local);
			if (getsockname(s, (struct sockaddr*)&local, &ll) == 0) {
				char ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
				result = ip;
			}
		}
		close(s);
	}
	freeaddrinfo(ai);
	return result;
}


// Resolve every IPv4 address a host maps to (control/DERP can be anycast to
// several), appending each as a dotted string. Used to carve out our own
// underlay endpoints from an exit node's full-tunnel capture.
static void
resolve_all_ipv4(const char* host, std::vector<BString>& out)
{
	if (host == NULL || *host == '\0')
		return;
	struct addrinfo hints;
	struct addrinfo* ai = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, NULL, &hints, &ai) != 0)
		return;
	for (struct addrinfo* p = ai; p != NULL; p = p->ai_next) {
		if (p->ai_family != AF_INET)
			continue;
		char ip[INET_ADDRSTRLEN];
		struct sockaddr_in* sin = (struct sockaddr_in*)p->ai_addr;
		if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) != NULL)
			out.push_back(BString(ip));
	}
	freeaddrinfo(ai);
}


void
TailscaleBackend::_RunMap(ts::ControlSession& session, BMessenger& self)
{
	// Open the UDP socket up front so every MapRequest -- the first and every
	// reconnect -- can advertise a real endpoint (our LAN address + magicsock
	// port). Control relays it to peers, who disco-ping us to open a direct path.
	if (!fMagicSock.IsOpen())
		fMagicSock.Open(0);

	// First map session. If it never even comes up, surface the error the way a
	// fresh Connect expects rather than silently retrying forever.
	bool established = false;
	bigtime_t start = system_time();
	_RunMapSession(session, self, &established);
	if (fStopRequested) {
		fMagicSock.Close();
		BMessage done(kMsgTsFailed);
		done.AddString("detail", "");	// stopped
		self.SendMessage(&done);
		return;
	}
	if (!established) {
		fMagicSock.Close();
		BMessage m(kMsgTsFailed);
		const char* detail = session.LastError();
		m.AddString("detail", (detail != NULL && *detail != '\0')
			? detail : "network map request failed");
		self.SendMessage(&m);
		return;
	}

	// The data plane is up. From here a dropped control stream must NOT tear the
	// VPN down -- the tun, DERP relay and negotiated peer sessions keep carrying
	// traffic while we re-establish the long-poll with backoff, until the user
	// disconnects. (Rekey and DERP live independently of the control channel.)
	ts::ReconnectBackoff backoff(1000000LL /* 1s */, 30000000LL /* 30s */,
		30000000LL /* healthy >= 30s */);
	while (!fStopRequested) {
		bigtime_t lasted = system_time() - start;
		bigtime_t delay = backoff.NextDelay(established, lasted);
		printf("[tailscale] control map stream ended (up %llds) -- reconnecting "
			"in %llds\n", (long long)(lasted / 1000000),
			(long long)(delay / 1000000));
		if (!_SleepInterruptible(delay))
			break;	// stop requested during the wait

		start = system_time();
		established = false;
		_RunMapSession(session, self, &established);
	}

	fMagicSock.Close();	// worker owns the socket; close it as the map loop ends

	BMessage done(kMsgTsFailed);
	done.AddString("detail", "");	// stopped
	self.SendMessage(&done);
}


// Drive one control map long-poll to its end: (re)establish the connection, send
// the streaming MapRequest, and apply MapResponses until the stream drops or a
// stop is requested. On the first netmap it also brings up the data plane. Sets
// *outEstablished once the request is accepted (HTTP 200); the return status is
// the reason the session ended (B_OK == clean end / stopped), which the caller
// uses to decide whether and how long to back off before reconnecting. This
// function itself posts NO terminal kMsgTsFailed -- teardown is the caller's job.
status_t
TailscaleBackend::_RunMapSession(ts::ControlSession& session, BMessenger& self,
	bool* outEstablished)
{
	if (outEstablished != NULL)
		*outEstablished = false;

	uint16 version = ts::kControlProtocolVersion;

	// The register/poll/previous-map connections are closed by the server; open a
	// fresh handshake + HTTP/2 connection for this map long-poll.
	if (session.Establish() != B_OK)
		return B_IO_ERROR;
	// Wake the long-poll read every couple of seconds so the loop notices a
	// Disconnect promptly (the -2/would-block return just re-polls) instead of
	// blocking on the default 30s timeout.
	session.SetReadTimeout(2);

	// (Re)compute our advertised endpoint every time -- this picks up a changed
	// LAN address after roaming. The magicsock port is stable across reconnects.
	BString endpointsJson;
	if (fMagicSock.IsOpen()) {
		BString lan = local_ipv4(fControlHost.String());
		if (lan.Length() > 0) {
			endpointsJson.SetToFormat("\"%s:%u\"", lan.String(),
				(unsigned)fMagicSock.LocalPort());
			printf("[tailscale] advertising endpoint %s\n",
				endpointsJson.String());
		}
	}

	ts::MapStream map;
	int status = 0;
	status_t result = map.Begin(session.Http2(), fControlHost.String(), version,
		fIdentity.NodePublic(), fIdentity.DiscoPublic(), fHostname.String(),
		endpointsJson.String(), true /* stream */, &status);
	if (result != B_OK || status != 200)
		return B_IO_ERROR;
	if (outEstablished != NULL)
		*outEstablished = true;

	// Stream MapResponses: the first is the full snapshot, then deltas. Apply
	// each to the session state and post a netmap summary.
	BString msg;
	while (!fStopRequested) {
		status_t r = map.ReadMessage(msg);
		if (r == B_ENTRY_NOT_FOUND)
			return B_OK;	// clean end of stream -> reconnect
		if (r == B_WOULD_BLOCK)
			continue;	// quiet period between keepalives -- keep polling
		if (r != B_OK)
			return r;	// read error (e.g. control drop) -> caller backs off
		fSessionLock.Lock();
		bool ok = fSession.ApplyMapResponse(msg.String(), msg.Length());
		fSessionLock.Unlock();
		if (!ok)
			continue;	// skip a malformed message, keep the stream

		// On the first netmap bring up the data plane: STUN for our public
		// endpoint, put our tailnet address on the tun, start the packet reader
		// threads, connect DERP and the MagicDNS resolver. Gated on the tun not
		// being up yet, so reconnects don't re-run it.
		if (fTunFd < 0) {
			_BringUpMagicSock(self);
			BString selfip = fSession.SelfIPv4();
			if (fTunInterface.Length() == 0 && selfip.Length() > 0)
				_BringUpTun(selfip.String());
			if (fMagicSock.IsOpen() && fTunFd < 0 && fTunNode.Length() > 0)
				_StartDataPlane();
			_BringUpDerp();
			// Now that we know which DERP region we're homed on, tell control
			// (plus our LAN endpoint) so peers have a return path to us.
			if (fDerpUp && fDerpHomeRegion > 0)
				_AdvertiseDerpHome(endpointsJson.String());
			_StartMagicDns();
		}

		// Reconcile subnet-router routes against this netmap (peers advertising
		// non-tailnet CIDRs can appear/withdraw at any update).
		_SyncRoutes();

		BMessage nm(kMsgTsNetmap);
		nm.AddInt32("peers", fSession.PeerCount());
		nm.AddString("selfip", fSession.SelfIPv4());
		// The tunnel is genuinely up once the tun device is open and reading;
		// tell the looper so it can flip the session to CONNECTED rather than
		// sitting in AUTHENTICATING forever.
		nm.AddBool("up", fTunFd >= 0);
		self.SendMessage(&nm);
	}
	return B_OK;	// stopped
}


// Sleep up to `usec`, but wake and return false the moment a stop is requested,
// so a Disconnect during a reconnect backoff is honoured within ~200ms.
bool
TailscaleBackend::_SleepInterruptible(bigtime_t usec)
{
	const bigtime_t kSlice = 200000;	// 200ms
	bigtime_t waited = 0;
	while (waited < usec) {
		if (fStopRequested)
			return false;
		bigtime_t chunk = (usec - waited) < kSlice ? (usec - waited) : kSlice;
		snooze(chunk);
		waited += chunk;
	}
	return !fStopRequested;
}


void
TailscaleBackend::_BringUpMagicSock(BMessenger& self)
{
	// The socket may already be open (we open it before the MapRequest to
	// advertise our endpoint); only Open it if needed, but still run the STUN
	// endpoint discovery below either way.
	if (!fMagicSock.IsOpen() && fMagicSock.Open(0) != B_OK) {
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
