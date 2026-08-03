# Sotoportego — Tailscale backend design (level C: full Tailscale)

Status: **draft / in progress** — see `ROADMAP.md` for the phased plan and
`PROGRESS.md` for the live build log.

This document describes how a *full* Tailscale client ("level C") is built
inside Sotoportego, in-process and from scratch, the same way the existing
`WireGuardBackend` was. It is the reference the loop-mode build follows.

---

## 1. Scope and non-goals

**In scope (level C):**

* Join a real tailnet, authenticated through the browser login flow, against
  either the official coordination server (`controlplane.tailscale.com`) or a
  self-hosted **Headscale**.
* The full control-plane client (`ts2021` Noise channel, node registration,
  the long-poll network-map stream).
* NAT traversal: endpoint discovery (STUN), the `disco` peer-probing protocol,
  direct UDP hole-punching, and **DERP** relay fallback so connectivity works
  even when a direct path can't be established.
* WireGuard data plane driven from the network map (peers, keys, endpoints,
  AllowedIPs), reusing the existing in-process WireGuard implementation.
* MagicDNS (the `100.100.100.100` resolver) and accepting advertised routes.

**Explicit non-goals for the first shippable version:**

* Being an *exit node* or a *subnet router* (advertising routes/exit) — we are
  a leaf node first; advertising comes later.
* Taildrop, SSH, serve/funnel, and other higher-level features.
* IPv6 *inside* the tunnel — blocked by Haiku's `tunnel` driver exactly as it
  is for the WireGuard backend (see the main README roadmap). Tailscale's
  control and DERP traffic over IPv6 on the *underlay* is fine; only the
  in-tunnel `AF_INET6` is blocked.

---

## 2. Why this is mostly a control-plane and NAT-traversal project

Tailscale is **WireGuard for the data plane plus a large coordination layer on
top**. Sotoportego already owns the hard cryptographic part of the data plane:
`src/backend/WireGuardBackend.*` and `src/backend/WireGuardCrypto.*` implement
the Noise IKpsk2 handshake, ChaCha20-Poly1305 transport, rekey, RFC 6479
anti-replay and AllowedIPs routing, validated against a real WireGuard server.

What Tailscale adds — and what this project must build from nothing on Haiku —
is everything that decides *who* the WireGuard peers are and *how packets reach
them*:

| Layer | Tailscale component | Have it? | Notes |
|---|---|---|---|
| Data plane crypto | wireguard-go | **Yes** | `WireGuardCrypto` + `WireGuardBackend` transport loop |
| Control channel crypto | Noise IK (`ts2021`) | **Reusable** | Same suite as WireGuard: X25519 + ChaCha20Poly1305 + BLAKE2s |
| Control transport | HTTP/2 over TLS to control | No | Needs a TLS client (OpenSSL is already linked) |
| Node registration + login | `controlclient` | No | Browser auth URL flow |
| Network map | `MapRequest`/`MapResponse` long poll | No | JSON `tailcfg` types |
| Endpoint discovery | STUN | No | Small, self-contained |
| Peer probing | `disco` (NaCl box) | No | **New crypto**: Curve25519 + XSalsa20-Poly1305 |
| NAT traversal | `magicsock` | No | The largest single piece |
| Relay fallback | DERP client | No | Long-lived HTTP framed protocol over TLS |
| Name resolution | MagicDNS | No | A local resolver on 100.100.100.100 |

The two genuinely *new* crypto pieces are the `disco` protocol (NaCl box —
XSalsa20/Poly1305, which we do **not** have) and the TLS client for control +
DERP (delegated to OpenSSL). Everything Noise-shaped reuses `WireGuardCrypto`.

---

## 3. Where it plugs into the existing architecture

The daemon already exposes a clean backend seam; Tailscale becomes a fourth
backend behind it, changing no IPC, GUI, or daemon wiring beyond registration.

```
VPNBackend (src/backend/VPNBackend.h)         abstract seam, a BHandler
  ├─ OpenVPNBackend                           drives the openvpn binary
  ├─ WireGuardBackend                          in-process WG data plane
  └─ TailscaleBackend   ← NEW                  in-process full Tailscale
```

Concretely:

* `VPNBackendType` in `src/common/VPNProfile.h` gains `VPN_BACKEND_TAILSCALE = 3`.
* `SotoportegoServer` (`src/server/SotoportegoServer.cpp`) constructs a
  `fTailscale` alongside `fOpenVPN`/`fWireGuard` and returns it from
  `_SelectBackend()`.
* The GUI backend-label switch (`src/gui/MainWindow.cpp`) learns the new type.
* A tailnet "profile" is not a file import like `.ovpn`/`.conf`; it is a
  persistent identity (machine key + node key + control URL + last auth state)
  stored under `~/config/settings/Sotoportego/tailscale/`. `VPNProfile` grows an
  optional control-URL field, or we store identity out-of-band keyed by profile
  name — decided in Phase 1.

`TailscaleBackend` satisfies the same contract as the others: `Connect()` /
`Disconnect()` return immediately, all state mutation happens on the daemon
looper, and worker threads post results back with `BMessenger(this)`.

### 3.1 Reused vs. new modules

```
REUSED (as-is or lightly generalized):
  src/backend/WireGuardCrypto.*     Noise IK, HKDF/BLAKE2s, X25519, ChaCha20Poly1305
  src/backend/TunDevice.*           tun/N bring-up + route install
  src/common/WireGuardRoutes.*      AllowedIPs → route plumbing
  GeoLookup / HTTP helpers          pattern for background HTTP workers

NEW under src/backend/tailscale/ (proposed):
  TSNoise.*            ts2021 control-channel Noise IK over a byte stream
  TSControlClient.*    register + map long-poll; owns the netmap
  TSNetmap.*           parsed tailcfg types (Node, DERPMap, DNSConfig, ...)
  TSDisco.*            disco protocol: NaCl box + ping/pong endpoint probes
  MagicSock.*          UDP socket mux: STUN, disco, direct paths, DERP send/recv
  DERPClient.*         one long-lived framed TLS connection per home region
  STUN.*               minimal STUN binding request/response
  NaClBox.*            Curve25519 + XSalsa20-Poly1305 (new crypto primitive)
  MagicDNS.*           100.100.100.100 stub resolver
  TailscaleBackend.*   orchestrator implementing VPNBackend

NEW under src/common/:
  TSConfig.*           control URL, auth key, persisted identity
```

---

## 4. Component design

### 4.1 Identity and keys

Three key types, all persisted (the machine key must survive restarts so the
node isn't re-registered every launch):

* **Machine key** — Curve25519, long-lived. Identifies the device to the
  control server and secures the `ts2021` Noise channel.
* **Node key** — Curve25519, this is the WireGuard key advertised to peers.
  Rotatable and expirable; the control server may ask us to rotate.
* **Disco key** — Curve25519, used only by the `disco` probing protocol so
  endpoint discovery can't be correlated to the node key.

Keys live under `~/config/settings/Sotoportego/tailscale/<profile>/` with the
private material stored via the Haiku keystore (`BKeyStore`) exactly like the
remembered OpenVPN password, never in a plain file.

### 4.2 Control client (`TSControlClient`, `TSNoise`)

The modern Tailscale control protocol ("noise" / `ts2021`) runs a **Noise IK**
handshake — the same pattern `WireGuardCrypto` already implements — over an
HTTP/2 stream to `<control>/ts2021`, then carries length-prefixed JSON control
messages inside the encrypted channel. Sequence:

1. `POST /ts2021` upgrade → establish the Noise IK session using the machine
   key as the static key, the control server's key as the responder. Reuse the
   Noise mix/HKDF/DH helpers from `WireGuardCrypto`, generalized to run over an
   arbitrary byte stream instead of a UDP datagram.
2. `RegisterRequest` with the node key. If the node isn't pre-authorized the
   response carries an **`AuthURL`**; the backend surfaces it to the daemon,
   which opens it with `be_roster` / notifies the GUI so the user completes
   login in a browser. We poll registration until the node is authorized (or an
   auth key was supplied for non-interactive join).
3. `MapRequest` opens a **long-poll stream**; the server streams `MapResponse`
   objects (full snapshot first, then deltas) for the life of the session. Each
   carries the peer list, their keys/endpoints/DERP-home, `AllowedIPs`, the
   `DERPMap`, and DNS config. Parsing lands in `TSNetmap`.

Transport is HTTP/2 over TLS via OpenSSL. If HTTP/2 proves painful on Haiku's
OpenSSL, the protocol also works over HTTP/1.1 with the Noise bytes framed in
the body; Phase 2 picks the simplest path that the control server accepts.

### 4.3 The network map (`TSNetmap`)

The netmap is the single source of truth for the data plane. On each
`MapResponse` the backend recomputes the WireGuard peer set:

* For every peer node: public (node) key, its candidate endpoints, its DERP
  home region, and its `AllowedIPs` (the peer's Tailscale IP(s) plus any
  subnet routes it advertises and we accept).
* Our own Tailscale IPv4 (a `100.64.0.0/10` CGNAT address) → assigned to the
  `tun/N` interface.
* DNS config → handed to MagicDNS.

Changes are diffed and pushed into the WireGuard engine (add/remove/update
peer) and into `MagicSock` (which paths to probe).

### 4.4 magicsock — the heart of it (`MagicSock`, `STUN`, `TSDisco`)

`MagicSock` is one UDP socket (per address family) that multiplexes several
protocols by inspecting the first bytes of each datagram:

* **STUN** responses — learn our public `ip:port` as seen by DERP's STUN
  service, for each interface. Produces our "endpoints" reported to control.
* **disco** messages (magic prefix `TS💬`) — NaCl-box-encrypted ping/pong the
  peers exchange to discover a working direct path and keep it alive. This is
  the hole-punching driver.
* **WireGuard** transport packets — anything else is a real data packet handed
  to the WireGuard transport loop.

Path selection per peer: start relaying through DERP immediately (so traffic
flows from t=0), simultaneously send disco pings to every candidate endpoint;
when a disco pong returns on a direct path, upgrade that peer to the direct UDP
endpoint and stop relaying. If the direct path goes quiet, fall back to DERP.
This "DERP-then-upgrade" is exactly Tailscale's behavior and it is what makes
the connection feel instant while still becoming peer-to-peer.

`disco` needs **NaCl box** (Curve25519 key agreement + XSalsa20-Poly1305), a
primitive not in the current tree — implemented in `NaClBox.*` (Phase 4).

### 4.5 DERP client (`DERPClient`)

DERP (Designated Encrypted Relay for Packets) servers relay WireGuard packets
between nodes that can't reach each other directly, and also provide the STUN
service. One long-lived TLS connection to our home-region DERP server:

* Framed binary protocol (frame type + length + payload) over TLS.
* On connect, send our node public key; thereafter `SendPacket(dstKey, bytes)`
  and receive `RecvPacket(srcKey, bytes)` frames.
* The relayed payload is the *already WireGuard-encrypted* packet — DERP never
  sees plaintext. DERP is chosen from the `DERPMap` in the netmap.

DERP is on the critical path for first-packet connectivity, so it is built
early (Phase 5) and direct-path upgrade (Phase 6) layers on top.

### 4.6 Data plane integration

The existing `WireGuardBackend` transport loop assumes a *single* peer with a
*static* `Endpoint`. For Tailscale it must:

* support **N peers**, keyed by node public key;
* get each peer's send path from `MagicSock` (a direct `sockaddr` or "via
  DERP") instead of a fixed endpoint;
* run one Noise handshake per peer, lazily on first traffic.

This is a generalization of `WireGuardBackend`, not a rewrite: the encrypt/
decrypt, rekey and anti-replay code is per-peer state. Phase 3 refactors the
transport core into a reusable `WGPeer` unit that both backends share.

### 4.7 MagicDNS (`MagicDNS`)

A stub resolver bound to `100.100.100.100:53` on the tun interface: answers
`*.<tailnet>.ts.net` from the netmap's peer list, forwards everything else to
the upstream resolvers the netmap specifies. On a full setup the system
resolver is pointed at `100.100.100.100` using the same `resolv.conf`
save/restore dance the WireGuard backend already does for full-tunnel DNS.

---

## 5. Connection lifecycle (state machine)

```
DISCONNECTED
   │ Connect(profile)
   ▼
INITIALIZING        load/generate keys, bring up tun/N, open magicsock UDP
   ▼
CONTROL_HANDSHAKE   ts2021 Noise IK to control
   ▼
AUTHENTICATING      RegisterRequest → (AuthURL surfaced to user if needed)
   ▼
MAP_SYNC            first MapResponse received → build netmap
   ▼
NAT_DISCOVERY       STUN sweep, DERP home connected, endpoints reported
   ▼
CONNECTED           ≥1 peer reachable (via DERP immediately, direct as it upgrades)
   │ Disconnect() / fatal error / control stream drop
   ▼
DISCONNECTED        tear down peers, magicsock, DERP, tun/N, restore DNS/routes
```

State is reported through the existing `NotifyStateChanged` / `kMsgStatusUpdate`
path, so the GUI header dot and event log light up with no GUI changes beyond
mapping the new detail strings. `AUTHENTICATING` with an `AuthURL` is the one
new interaction the GUI must handle (show/open the login link).

---

## 6. Threading model

Mirrors the existing backends: all state lives on the daemon looper; workers
post back via `BMessenger(this)`.

* **Control thread** — runs the `ts2021` handshake and blocks on the map
  long-poll; posts each parsed `MapResponse` to the looper.
* **magicsock reader thread** — blocks on the UDP socket, demultiplexes
  STUN/disco/WireGuard, posts disco/STUN results to the looper and feeds
  WireGuard packets straight into the transport path.
* **DERP reader thread** — blocks on the DERP TLS connection, posts relayed
  packets in.
* **tun reader thread** — reads outbound IP packets off `tun/N` (reused from
  the WireGuard backend).
* Periodic timers (`BMessageRunner`): STUN re-probe, disco keepalive, netmap
  keepalive, WireGuard rekey.

No locks on backend state: the looper serializes everything, as in
`WireGuardBackend`.

---

## 7. Crypto inventory

| Primitive | Where used | Source |
|---|---|---|
| Curve25519 (X25519) | Noise DH, disco, node/machine keys | OpenSSL (already linked) |
| ChaCha20-Poly1305 | WG transport + Noise | `WireGuardCrypto` (have it) |
| BLAKE2s | Noise hashing / HKDF | bundled in `WireGuardCrypto` (have it) |
| Noise IK | WG handshake + `ts2021` control | `WireGuardCrypto`, generalized |
| **XSalsa20-Poly1305 (NaCl box)** | **disco** | **new — `NaClBox.*`** |
| TLS 1.2/1.3 client | control HTTP/2, DERP | OpenSSL (already linked) |

Only one new primitive (NaCl box) and one new dependency surface (OpenSSL TLS
client, where today we only call OpenSSL for X25519).

---

## 8. Security & privilege notes

* Private keys never touch a plaintext file — Haiku keystore, as with the
  remembered OpenVPN secret.
* The daemon stays the single privileged owner of tun/route/DNS state; the GUI
  only ever sees state broadcasts and the AuthURL.
* `RecoverIfCrashed()` must roll back tun/N, routes and `resolv.conf` left by a
  crashed session, extending the WireGuard backend's recovery logic.
* Treat everything in a `MapResponse` as untrusted server input: bound array
  sizes, validate key lengths, and never let an advertised route replace the
  default route unless the user opted into "accept routes" / exit-node use.

---

## 9. Testing strategy

* **Unit**: NaCl box test vectors; STUN encode/decode; Noise `ts2021` handshake
  against a captured control transcript; netmap JSON parse fixtures.
* **Integration against Headscale** (self-hosted) first — reproducible, no
  account, and it speaks the same protocol. A local Headscale in a VM is the
  primary dev target.
* **Interop**: once Headscale works, validate against the official coordination
  server with a real tailnet.
* **On-device (Haiku)**: the same `scripts/verify-tunnel.sh` proves outbound
  traffic actually rides the tunnel; add a check that two tailnet nodes can
  ping each other over their `100.x` addresses, first via DERP then direct.

The main README keeps `docs/` off the shipping tree, so this feature's
design/roadmap/progress live under `design/tailscale/` on the `Tailscale`
branch to coordinate the loop-mode build; they can be squashed out before any
release merge.
