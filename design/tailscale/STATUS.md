# Sotoportego Tailscale backend — status & module map

A from-scratch, in-process Tailscale ("level C") client for Haiku, built in C++
with no Go/Rust and only OpenSSL (already linked). This file is the navigable
overview of what exists, how each piece was verified, and the one area that still
needs a live two-node tailnet to finish. Per-iteration detail is in `PROGRESS.md`;
the architecture is in `DESIGN.md`; the phased plan is in `ROADMAP.md`.

## How things were verified

- **live** — exercised against the real coordination server
  (`controlplane.tailscale.com`) or a public STUN/DERP server from this Haiku box.
- **vector** — checked against a published test vector (RFC 7541 HPACK, NaCl box,
  etc.).
- **fixture** — checked against a synthetic input (a crafted MapResponse, DNS
  query, …).
- **round-trip** — encode↔decode / seal↔open within the process.
- **builds** — compiles into the daemon on Haiku (integration/orchestration whose
  full behaviour needs a live tailnet).

## Module map (`src/backend/tailscale/`)

| Module | Role | Verified |
|---|---|---|
| `TailscaleBackend` | VPNBackend impl; control worker thread; state machine; drives register + map | builds (live control flow) |
| `TSConfig` (common) | per-profile control URL + on-disk identity layout | builds |
| `TSIdentity` | machine/node/disco Curve25519 keys, keystore-persisted | round-trip (hex+X25519) |
| `TSNoise` | Noise IK (ts2021) handshake state machine | round-trip (init↔resp keys) |
| `TSTls` | OpenSSL TLS client + one-shot HTTPS GET | live (`/key`, cert-verified) |
| `TSControl` | ts2021 framing (initiation/record) + `/key` mkey parse | live + fixture |
| `TSControlClient` | HTTP-Upgrade `/ts2021` + Noise handshake over TLS | **live handshake** |
| `TSControlConn` | encrypted record stream (BE-nonce ChaCha20-Poly1305) | **live** (records decrypt) |
| `TSHttp2` | HTTP/2 framing + SETTINGS + HPACK request/response + streaming | **live** (server 200/404) |
| `TSHpack` | HPACK encoder/decoder + Huffman | vector (RFC 7541 C.3/C.4/C.6) |
| `TSControlSession` | handshake→HTTP/2→register in one object | **live** (AuthURL) |
| `TSRegister` | JSON RegisterRequest/Response, followup poll | **live** (real AuthURL) |
| `TSMap` | MapRequest + streamed MapResponse de-framer | live (transport) + builds |
| `TSJson` | recursive JSON DOM parser | fixture |
| `TSNetmap` | parse MapResponse → self/peers/DERPMap/DNS | fixture |
| `TSPeerSet` | reconcile WGPeers from the netmap | fixture |
| `PeerPath` | DERP-then-upgrade send-path state machine | fixture (clock) |
| `TSSessionState` | apply one MapResponse → peers+DNS+self | fixture |
| `NaClBox` | Curve25519 + XSalsa20-Poly1305 (disco crypto) | vector (canonical NaCl) |
| `TSStun` | STUN binding request/parse | live (public endpoint) |
| `TSDisco` | disco Ping/Pong seal/open | round-trip |
| `TSDerp` | DERP relay client (framed TLS) | **live handshake** |
| `MagicSock` | UDP socket + STUN/disco/WG demux + STUN sweep | live (reflexive endpoint) |
| `WGPeer` | per-peer WireGuard: IKpsk2 handshake + type-4 transport + replay | round-trip + WGBackend-proven |
| `TSMagicDns` | MagicDNS stub resolver, netmap-populated | fixture |

Data-plane primitives reused from the WireGuard backend: `WireGuardCrypto`
(BLAKE2s/X25519/ChaCha20-Poly1305), `TunDevice` (tun bring-up + routes),
`WireGuardRoutes`.

### Regression suite

`src/backend/tailscale/tests/` holds a committed offline self-test
(`make test` → 34 checks) over the deterministic modules: crypto vs published
vectors, wire codecs by round-trip, and netmap/peer/DNS/route logic vs fixtures.
Run it after touching any of those modules. The live checks (control handshake,
STUN, DERP) are separate and need network.

## End-to-end proven against real Tailscale

From this Haiku box, against `controlplane.tailscale.com`: TLS `/key` fetch →
ts2021 Noise handshake → encrypted record stream → HTTP/2 + HPACK →
`RegisterRequest` returning a real `https://login.tailscale.com/a/…` **AuthURL**
(auto-opened by the GUI). STUN returned our public endpoint; the DERP relay
accepted our handshake. The whole control plane is interoperable with production
Tailscale.

## Prior art: the Go port on Haiku (rainygirl/haiku-i386-tailscale-patch)

The one existing attempt to run Tailscale on Haiku patches the **official Go**
`tailscaled` for i386. Two takeaways confirm this project's direction:

1. **The Go route is a runtime nightmare on Haiku** — the patch needs a custom
   `poll(2)` netpoller, async-preemption fixes, an `osyield()` 64-bit bug fix,
   `mmap` fixes, cross-compile-only builds (`x/sys/unix` has no Haiku), and it
   pins `GOMAXPROCS=1` + `GODEBUG=asyncpreemptoff=1`. Our from-scratch **C++ /
   OpenSSL** client sidesteps that entire class of problems — none of those
   runtime issues exist for us.
2. **It runs in userspace-networking mode with NO TUN device** — it avoids
   Haiku's tunnel driver entirely and exposes connectivity via `tailscale nc`
   (e.g. as an SSH ProxyCommand) instead of a real `tun/N`. That is a strong
   signal that Haiku's `tun` read/write path is the risky unknown (the same
   caveat the WireGuard backend already carries).

**Action for us:** verify `tun/N` read/write early on real hardware; and add a
**userspace-networking fallback** — a local SOCKS5 / port-forward front-end over
`WGPeer` transport that reaches peers *without* the tun (the Go port's approach),
so the client is useful even if the tunnel driver can't carry raw IP. Our
transport (`WGPeer` encap/decap) already works independently of the tun, so the
fallback is mostly a socket front-end.

## What remains — the packet data plane (needs a live tailnet)

The only unfinished area is the on-device packet path, which the design flags as
requiring a live dev target (a Headscale VM or a two-node tailnet):

1. Bring up `tun/N` and assign `TSSessionState::SelfIPv4()` (reuse `TunDevice`).
2. A magicsock **reader thread**: `Recv` → `Classify` → disco (feed `PeerPath`
   via `TSDisco`), STUN (endpoint refresh), or WireGuard (`WGPeer::Decapsulate`
   → write to tun).
3. A tun **reader thread**: read outbound IP packets → look up the peer by
   AllowedIPs → `WGPeer::Encapsulate` → send on the peer's `PeerPath` (direct
   `MagicSock::SendTo`, else `DerpClient::SendPacket`).
4. Per-peer `WGPeer::BuildInitiation`/`ConsumeResponse` lazily on first traffic;
   disco ping sweep to upgrade DERP→direct.
5. Install AllowedIPs routes (`WireGuardRoutes`) and bind `TSMagicDns` on
   `100.100.100.100:53` with upstream forwarding + `resolv.conf` save/restore.
6. `RecoverIfCrashed()` rollback of tun/routes/DNS.

Every building block these steps call is already implemented and verified above;
what's left is the threaded orchestration and its on-hardware validation.

## Runbook to finish + verify (Headscale)

1. `headscale` in a VM; create a user + a **pre-auth key**.
2. Point a Tailscale profile's control URL at the Headscale URL and set the
   pre-auth key (wire it through `TSConfig`/`RegisterResponseAuth.AuthKey`, which
   `TSRegister` already supports) → registration is non-interactive, so the map
   long-poll returns a real netmap the backend already applies.
3. Implement the data-plane threads (above); confirm two nodes `ping` each
   other's `100.x` first via DERP, then over a direct hole-punched path
   (`scripts/verify-tunnel.sh` + DERP counters).
