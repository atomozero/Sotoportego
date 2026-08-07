/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * Bench test for the Tailscale data plane's WireGuard session lifetime: rekey
 * timing, make-before-break, persistent keepalive, dead-session expiry, the
 * responder handshake path, and -- the headline -- a sustained bidirectional
 * session driven over 30 minutes of *simulated* time in which both ends rekey in
 * turn. It reproduces (and now guards against) the "connection drops after ~5
 * minutes" bug, which was a session that was never rekeyed.
 *
 * No network and no real waiting: WGPeer's injectable test clock (SetTestClock)
 * lets us fast-forward the session clock deterministically. Build + run with the
 * Makefile here:  make bench
 */
#include <cstdio>
#include <cstring>

#include <SupportDefs.h>

#include "TSBackoff.h"
#include "TSRoutes.h"
#include "WGPeer.h"
#include "WireGuardCrypto.h"

using namespace ts;

static bool
has_route(const std::vector<SubnetRoute>& v, const char* net, const char* mask)
{
	for (size_t i = 0; i < v.size(); i++) {
		if (v[i].net == net && v[i].mask == mask)
			return true;
	}
	return false;
}

static bool
has_ip(const std::vector<BString>& v, const char* ip)
{
	for (size_t i = 0; i < v.size(); i++) {
		if (v[i] == ip)
			return true;
	}
	return false;
}

static int sFail = 0;
static int sPass = 0;
#define CHECK(cond, msg) do { \
	if (cond) { sPass++; } \
	else { sFail++; printf("  FAIL: %s\n", msg); } \
} while (0)

// The WireGuard lifetime constants, mirrored here in microseconds so the bench
// can step around the boundaries.
static const bigtime_t S			= 1000000LL;
static const bigtime_t kRekeyAfter	= 120 * S;
static const bigtime_t kRejectAfter	= 180 * S;
static const bigtime_t kKeepalive	= 25 * S;


// Run a full synchronous handshake: `ini` (with static iPriv/iPub) initiates to
// `res` (static rPriv/rPub), the whole exchange settling at simulated time `t`.
// This mirrors the backend's initiator + responder paths end to end. Returns
// true only if both ends end up with matching transport keys.
static bool
handshake(WGPeer& ini, const uint8 iPriv[32], const uint8 iPub[32],
	WGPeer& res, const uint8 rPriv[32], const uint8 rPub[32], bigtime_t t)
{
	ini.SetTestClock(t);
	res.SetTestClock(t);

	uint8 m1[148];
	if (ini.BuildInitiation(iPriv, rPub, m1) != 148)
		return false;
	uint8 recovered[32];
	if (!WGPeer::RecoverInitiatorStatic(rPriv, m1, 148, recovered)
			|| memcmp(recovered, iPub, 32) != 0)
		return false;
	if (!res.ConsumeInitiation(rPriv, m1, 148))
		return false;
	uint8 m2[92];
	if (res.BuildResponse(m2) != 92)
		return false;
	if (!ini.ConsumeResponse(m2, 92))
		return false;
	return ini.HasKeys() && res.HasKeys();
}


// Encapsulate a small IPv4 packet on `from` and confirm `to` decapsulates it
// intact -- i.e. their live session keys still agree.
static bool
data_ok(WGPeer& from, WGPeer& to)
{
	uint8 ip[40];
	memset(ip, 0, sizeof(ip));
	ip[0] = 0x45;			// IPv4, IHL 5
	ip[2] = 0; ip[3] = 40;	// total length 40
	ip[9] = 17;				// UDP, just for shape
	ip[19] = 0x2a;

	uint8 enc[128];
	size_t n = from.Encapsulate(ip, sizeof(ip), enc);
	if (n == 0)
		return false;
	uint8 out[128];
	ssize_t d = to.Decapsulate(enc, n, out);
	return d == (ssize_t)sizeof(ip) && memcmp(out, ip, sizeof(ip)) == 0;
}


static void
make_keypair(uint8 priv[32], uint8 pub[32])
{
	wg::DhGenerate(priv, pub);
}


// --- scenario 1: lifetime-timer edges are where the protocol says ------------
static void
test_lifetime_timers()
{
	uint8 iPriv[32], iPub[32], rPriv[32], rPub[32];
	make_keypair(iPriv, iPub);
	make_keypair(rPriv, rPub);
	WGPeer ini, res;
	bigtime_t T = 1000 * S;
	CHECK(handshake(ini, iPriv, iPub, res, rPriv, rPub, T), "timers: handshake up");

	CHECK(!ini.ShouldInitiateRekey(T), "timers: no rekey at age 0");
	CHECK(!ini.ShouldKeepalive(T), "timers: no keepalive right after install");
	CHECK(!ini.ShouldInitiateRekey(T + kRekeyAfter - S),
		"timers: no rekey just before REKEY_AFTER_TIME");
	CHECK(ini.ShouldInitiateRekey(T + kRekeyAfter),
		"timers: rekey due at REKEY_AFTER_TIME");
	CHECK(ini.ShouldKeepalive(T + kKeepalive),
		"timers: keepalive due after idle window");
	CHECK(ini.SessionAgeSeconds(T + 45 * S) == 45, "timers: session age reported");
	CHECK(res.SessionAgeSeconds(T + 45 * S) == 45, "timers: responder age reported");
}


// --- scenario 2: rekey retransmit throttle + make-before-break ---------------
static void
test_make_before_break()
{
	uint8 iPriv[32], iPub[32], rPriv[32], rPub[32];
	make_keypair(iPriv, iPub);
	make_keypair(rPriv, rPub);
	WGPeer ini, res;
	bigtime_t T = 2000 * S;
	CHECK(handshake(ini, iPriv, iPub, res, rPriv, rPub, T), "mbb: initial session up");

	// At REKEY_AFTER_TIME the initiator sends a fresh initiation but MUST keep
	// using the current keys until the response lands.
	bigtime_t t2 = T + kRekeyAfter;
	ini.SetTestClock(t2);
	uint8 m1[148];
	CHECK(ini.BuildInitiation(iPriv, rPub, m1) == 148, "mbb: rekey initiation built");
	CHECK(ini.HasKeys() && data_ok(ini, res),
		"mbb: old keys still carry data while rekey is in flight");

	// Retransmit is throttled for REKEY_TIMEOUT (5s) then allowed again.
	CHECK(!ini.ShouldInitiateRekey(t2 + 2 * S), "mbb: rekey throttled within 5s");
	CHECK(ini.ShouldInitiateRekey(t2 + 6 * S), "mbb: rekey retransmit after 5s");

	// The peer answers: consume the initiation, respond, initiator installs the
	// new keys. Both must then talk on the fresh session, both directions.
	res.SetTestClock(t2);
	CHECK(res.ConsumeInitiation(rPriv, m1, 148), "mbb: responder consumes rekey");
	uint8 m2[92];
	CHECK(res.BuildResponse(m2) == 92, "mbb: responder builds response");
	ini.SetTestClock(t2);
	CHECK(ini.ConsumeResponse(m2, 92), "mbb: initiator installs new keys");
	CHECK(data_ok(ini, res), "mbb: new session carries data (i->r)");
	CHECK(data_ok(res, ini), "mbb: new session carries data (r->i)");
	// The session clock reset, so it's young again.
	CHECK(ini.SessionAgeSeconds(t2) == 0, "mbb: rekeyed session age reset");
}


// --- scenario 3: a session with no rekey response dies at REJECT_AFTER_TIME ---
static void
test_expiry()
{
	uint8 iPriv[32], iPub[32], rPriv[32], rPub[32];
	make_keypair(iPriv, iPub);
	make_keypair(rPriv, rPub);
	WGPeer ini, res;
	bigtime_t T = 3000 * S;
	CHECK(handshake(ini, iPriv, iPub, res, rPriv, rPub, T), "expiry: session up");

	CHECK(!ini.ExpireIfStale(T + kRejectAfter - S) && ini.HasKeys(),
		"expiry: session alive just before REJECT_AFTER_TIME");
	CHECK(ini.ExpireIfStale(T + kRejectAfter + S) && !ini.HasKeys(),
		"expiry: session dropped past REJECT_AFTER_TIME");
}


// --- scenario 4: sustained bidirectional session over 30 min of sim time -----
// Two peers, both rekeying in turn per the WireGuard clock; every simulated
// second we push a packet each way and require it to arrive. Before the rekey
// work this failed within ~3-5 minutes; now it must run clean for the full 30.
static void
test_sustained_session()
{
	uint8 aPriv[32], aPub[32], bPriv[32], bPub[32];
	make_keypair(aPriv, aPub);
	make_keypair(bPriv, bPub);
	WGPeer a, b;	// a = "us", b = the peer

	bigtime_t T0 = 5000 * S;
	CHECK(handshake(a, aPriv, aPub, b, bPriv, bPub, T0), "sustained: initial handshake");

	int dataFailures = 0;
	int rekeysByA = 0;
	int rekeysByB = 0;
	int lostKeys = 0;
	const int kMinutes = 30;

	for (bigtime_t t = T0 + S; t <= T0 + kMinutes * 60 * S; t += S) {
		a.SetTestClock(t);
		b.SetTestClock(t);

		// Alternate who reaches the rekey boundary first each 2-minute window, so
		// both the initiator path (a->b) AND our responder path (b->a) get
		// exercised over the run.
		bool bInitiatesFirst = (((t - T0) / kRekeyAfter) % 2) == 1;

		WGPeer* order[2] = { &a, &b };
		const uint8* priv[2] = { aPriv, bPriv };
		const uint8* pub[2] = { aPub, bPub };
		const uint8* peerPriv[2] = { bPriv, aPriv };
		const uint8* peerPub[2] = { bPub, aPub };
		WGPeer* peer[2] = { &b, &a };
		if (bInitiatesFirst) {
			order[0] = &b; order[1] = &a;
			priv[0] = bPriv; priv[1] = aPriv;
			pub[0] = bPub; pub[1] = aPub;
			peerPriv[0] = aPriv; peerPriv[1] = bPriv;
			peerPub[0] = aPub; peerPub[1] = bPub;
			peer[0] = &a; peer[1] = &b;
		}

		for (int k = 0; k < 2; k++) {
			WGPeer& who = *order[k];
			WGPeer& other = *peer[k];
			who.ExpireIfStale(t);
			if (who.HasKeys() && who.ShouldInitiateRekey(t)) {
				if (handshake(who, priv[k], pub[k], other, peerPriv[k], peerPub[k], t)) {
					if (&who == &a) rekeysByA++; else rekeysByB++;
				}
				// Re-pin both clocks to t (handshake sets them, but be explicit).
				a.SetTestClock(t);
				b.SetTestClock(t);
			}
		}

		if (!a.HasKeys() || !b.HasKeys())
			lostKeys++;
		if (!data_ok(a, b)) dataFailures++;
		if (!data_ok(b, a)) dataFailures++;
	}

	CHECK(dataFailures == 0, "sustained: no dropped packets across 30 simulated minutes");
	CHECK(lostKeys == 0, "sustained: both ends keep a live session the whole run");
	CHECK(rekeysByA > 0, "sustained: our initiator rekey path exercised");
	CHECK(rekeysByB > 0, "sustained: our responder rekey path exercised");
	printf("  (sustained: %d a-rekeys, %d b-rekeys, %d data failures, %d key gaps)\n",
		rekeysByA, rekeysByB, dataFailures, lostKeys);
}


// --- scenario 5: keepalive actually keeps the send clock warm ----------------
static void
test_keepalive()
{
	uint8 iPriv[32], iPub[32], rPriv[32], rPub[32];
	make_keypair(iPriv, iPub);
	make_keypair(rPriv, rPub);
	WGPeer ini, res;
	bigtime_t T = 6000 * S;
	CHECK(handshake(ini, iPriv, iPub, res, rPriv, rPub, T), "keepalive: session up");

	// Idle past the keepalive window -> due; then send an empty keepalive packet
	// and confirm it decapsulates to a zero-length (keepalive) frame and clears
	// the timer.
	bigtime_t t = T + kKeepalive + S;
	CHECK(ini.ShouldKeepalive(t), "keepalive: due after idle");
	ini.SetTestClock(t);
	uint8 out[64];
	size_t n = ini.Encapsulate(NULL, 0, out);
	CHECK(n == 32, "keepalive: empty frame encapsulates to a bare tag");
	uint8 plain[64];
	CHECK(res.Decapsulate(out, n, plain) == 0, "keepalive: decapsulates as keepalive");
	CHECK(!ini.ShouldKeepalive(t), "keepalive: send cleared the timer");
}


// --- scenario 6: the control-map reconnect backoff policy --------------------
static void
test_reconnect_backoff()
{
	// min 1s, max 30s, "healthy" session >= 30s.
	ReconnectBackoff b(1 * S, 30 * S, 30 * S);
	const bigtime_t want[] = { 1, 2, 4, 8, 16, 30, 30 };
	bool grows = true;
	for (int i = 0; i < 7; i++) {
		if (b.NextDelay(false, 0) != want[i] * S)
			grows = false;
	}
	CHECK(grows, "backoff: geometric growth, capped at max");

	// A session that stayed up long enough is a transient drop -> reset to min.
	CHECK(b.NextDelay(true, 60 * S) == 1 * S, "backoff: healthy drop resets to min");

	// A flap (came up but died fast) must NOT reset -- it keeps growing.
	b.NextDelay(false, 0);					// 1s -> current now 2s
	CHECK(b.NextDelay(true, 5 * S) == 2 * S, "backoff: short session doesn't reset");

	b.Reset();
	CHECK(b.Current() == 1 * S, "backoff: explicit reset to min");

	// Saturation and the min floor hold regardless of parameters.
	ReconnectBackoff c(2 * S, 10 * S, 30 * S);
	bigtime_t last = 0;
	for (int i = 0; i < 20; i++)
		last = c.NextDelay(false, 0);
	CHECK(last == 10 * S, "backoff: saturates at max");
	ReconnectBackoff e(3 * S, 30 * S, 30 * S);
	CHECK(e.NextDelay(false, 0) == 3 * S, "backoff: first delay is the floor");
}


// --- scenario 7: subnet-route planning + reconciliation ----------------------
static void
test_subnet_routes()
{
	std::vector<BString> allowed;
	allowed.push_back("100.64.7.6/32");		// our peer's tailnet addr (on-link)
	allowed.push_back("192.168.1.0/24");	// a subnet router
	allowed.push_back("10.0.0.0/8");		// another subnet
	allowed.push_back("0.0.0.0/0");			// exit node (not auto-installed)
	allowed.push_back("fd7a:115c:a1e0::/48"); // IPv6 (unroutable on Haiku tun)
	allowed.push_back("192.168.1.0/24");	// duplicate

	std::vector<SubnetRoute> desired;
	ComputeSubnetRoutes(allowed, desired);
	CHECK(desired.size() == 2, "routes: only the two non-tailnet subnets kept");
	CHECK(has_route(desired, "192.168.1.0", "255.255.255.0"),
		"routes: /24 subnet with correct mask");
	CHECK(has_route(desired, "10.0.0.0", "255.0.0.0"),
		"routes: /8 subnet with correct mask");
	CHECK(!has_route(desired, "100.64.7.6", "255.255.255.255"),
		"routes: tailnet /32 excluded (already on-link)");
	CHECK(!has_route(desired, "0.0.0.0", "0.0.0.0"),
		"routes: default/exit-node excluded");

	// Reconcile: from {192.168.1.0/24} installed to the full desired set.
	std::vector<SubnetRoute> installed;
	SubnetRoute r24; r24.net = "192.168.1.0"; r24.mask = "255.255.255.0";
	installed.push_back(r24);

	std::vector<SubnetRoute> toAdd, toRemove;
	DiffRoutes(desired, installed, toAdd, toRemove);
	CHECK(toAdd.size() == 1 && has_route(toAdd, "10.0.0.0", "255.0.0.0"),
		"routes: diff adds the newly-advertised /8");
	CHECK(toRemove.empty(), "routes: diff removes nothing still advertised");

	// A subnet router withdraws 192.168.1.0/24: it should be scheduled for removal.
	std::vector<SubnetRoute> shrunk;
	SubnetRoute r8; r8.net = "10.0.0.0"; r8.mask = "255.0.0.0";
	shrunk.push_back(r8);
	DiffRoutes(shrunk, desired, toAdd, toRemove);
	CHECK(toRemove.size() == 1 && has_route(toRemove, "192.168.1.0", "255.255.255.0"),
		"routes: diff removes a withdrawn subnet");
}


// --- scenario 8: exit-node underlay carve-out planning -----------------------
static void
test_exit_carveouts()
{
	std::vector<BString> underlay;
	underlay.push_back("100.101.102.103");		// control server
	underlay.push_back("5.6.7.8");				// DERP relay
	underlay.push_back("5.6.7.8");				// duplicate DERP
	underlay.push_back("192.168.0.9");			// exit node candidate endpoint
	underlay.push_back("");						// empty
	underlay.push_back("derp1.tailscale.com");	// hostname (unresolved) -> drop
	underlay.push_back("fd7a:115c::1");			// IPv6 -> drop

	std::vector<BString> carve;
	ComputeExitCarveouts(underlay, carve);
	CHECK(carve.size() == 3, "carveouts: dedup + drop empty/non-IPv4");
	CHECK(has_ip(carve, "100.101.102.103") && has_ip(carve, "5.6.7.8")
		&& has_ip(carve, "192.168.0.9"), "carveouts: the three real IPs kept");

	// The path was relay-only when we enabled the exit node; now it upgrades to
	// direct and the endpoint must be pinned too.
	std::vector<BString> pinned;
	pinned.push_back("100.101.102.103");
	pinned.push_back("5.6.7.8");
	std::vector<BString> toAdd, toRemove;
	DiffCarveouts(carve, pinned, toAdd, toRemove);
	CHECK(toAdd.size() == 1 && has_ip(toAdd, "192.168.0.9"),
		"carveouts: diff pins the new direct endpoint");
	CHECK(toRemove.empty(), "carveouts: diff keeps control/DERP pinned");

	// The exit node roams to a new endpoint: the old pin must be removed.
	std::vector<BString> newer;
	newer.push_back("100.101.102.103");
	newer.push_back("5.6.7.8");
	newer.push_back("9.9.9.9");
	DiffCarveouts(newer, carve, toAdd, toRemove);
	CHECK(has_ip(toAdd, "9.9.9.9") && has_ip(toRemove, "192.168.0.9"),
		"carveouts: re-pins when the endpoint changes");
}


int
main()
{
	printf("Tailscale WireGuard session-lifetime bench (simulated time)\n---\n");
	test_lifetime_timers();
	test_make_before_break();
	test_expiry();
	test_sustained_session();
	test_keepalive();
	test_reconnect_backoff();
	test_subnet_routes();
	test_exit_carveouts();
	printf("---\n%d passed, %d failed\n", sPass, sFail);
	return sFail == 0 ? 0 : 1;
}
