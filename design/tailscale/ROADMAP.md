# Sotoportego — Tailscale roadmap (level C)

Phased plan for the full Tailscale backend. Each phase is a self-contained,
committable milestone with a concrete **Done when** check. The loop build works
top-to-bottom, ticking boxes and appending to `PROGRESS.md` after every
iteration. See `DESIGN.md` for the architecture these phases realize.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Phase 0 — Foundations & scaffolding
Goal: the seam exists and compiles; no behavior yet.

- [x] Add `VPN_BACKEND_TAILSCALE = 3` to `VPNProfile.h`; teach `VPNProfile`
      archive/unarchive and the GUI label switch about it. (Archive/unarchive is
      already backend-generic via `AddInt32`; GUI label switch updated.)
- [x] Create `src/backend/tailscale/` and a stub `TailscaleBackend` implementing
      `VPNBackend` (returns `B_NOT_SUPPORTED` from `Connect` for now).
- [x] Register `fTailscale` in `SotoportegoServer` + `_SelectBackend()` (+ ctor
      init, `ReadyToRun` construct/observe, `RecoverIfCrashed`).
- [x] `src/common/TSConfig.*`: control URL, optional auth key, persisted-identity
      paths under `~/config/settings/Sotoportego/tailscale/`.
- [x] Makefiles updated (server SRCS + include path); CLI/GUI need only the enum.
- **Done when:** `make` is green and selecting a Tailscale profile reaches the
      new backend (which cleanly reports "not implemented"). *(Done: `make` is
      green on-Haiku with TSConfig compiled into the daemon.)*

## Phase 1 — Identity & key management
Goal: stable machine/node/disco identity across restarts.

- [x] Generate & persist machine, node, disco Curve25519 keypairs.
- [x] Store private keys in the Haiku keystore (`BKeyStore`), never plaintext.
- [x] Load-or-create on `Connect`; expose public keys.
- **Done when:** two consecutive launches reuse the same machine key
      (unit-checkable without a network). *(Impl done in `TSIdentity`; keystore
      round-trip re-derives the same public key. Pure hex+X25519 path
      unit-verified on-Haiku; the two-launch keystore check is interactive —
      first keystore access may prompt to unlock the keyring — so verify from
      the GUI: connect a Tailscale profile twice, the log prints
      `generated` then `reused` with the same node key.)*

## Phase 2 — Control channel (`ts2021`) + registration
Goal: authenticate to a control server and hold an authorized session.

- [x] `TSNoise`: Noise IK over a byte stream, reusing `WireGuardCrypto` helpers.
      *(Generic IK state machine — SymmetricState + HandshakeState — done and
      unit-verified in-process: initiator↔responder derive identical transport
      keys + handshake hash, payloads round-trip, tampering rejected. The
      ts2021-specific outer framing (msg-type/version headers) is added with the
      transport, next.)*
- [ ] OpenSSL TLS client wrapper; HTTP transport to `<control>/ts2021`.
- [ ] `RegisterRequest`/`RegisterResponse`; surface `AuthURL` to the daemon →
      GUI opens the browser; poll to authorized. Support a pre-auth key path.
- **Done when:** against a local **Headscale**, the node registers and shows up
      as authorized in `headscale nodes list`.

## Phase 3 — Network map + WireGuard peer engine
Goal: turn a `MapResponse` into live WireGuard peer state.

- [ ] `MapRequest` long-poll; parse `MapResponse` into `TSNetmap`
      (nodes, keys, endpoints, DERP-home, AllowedIPs, DNS, DERPMap).
- [ ] Refactor `WireGuardBackend`'s transport core into a reusable per-peer
      `WGPeer` (handshake/transport/rekey/anti-replay), shared by both backends.
- [ ] Assign our `100.x` Tailscale IP to `tun/N`; program peers from the netmap.
- **Done when:** peers appear with correct keys/AllowedIPs and our tun has the
      tailnet IP (still no packet path yet — that's DERP/magicsock).

## Phase 4 — disco protocol + NaCl box + STUN
Goal: discover our endpoints and probe peers.

- [ ] `NaClBox`: Curve25519 + XSalsa20-Poly1305, verified against test vectors.
- [ ] `STUN`: binding request/response; learn public `ip:port` per interface.
- [ ] `TSDisco`: encode/decode disco ping/pong; report local endpoints to
      control on the next `MapRequest`.
- **Done when:** NaCl box vectors pass and STUN returns our public endpoint.

## Phase 5 — DERP relay (first connectivity)
Goal: packets flow between two tailnet nodes via relay.

- [ ] `DERPClient`: long-lived framed TLS connection to the home-region DERP
      from the `DERPMap`; send/recv relayed (already-WG-encrypted) packets.
- [ ] `MagicSock`: one UDP socket demuxing STUN/disco/WireGuard; route peer
      sends through DERP when no direct path exists.
- [ ] Wire DERP send/recv into the `WGPeer` transport path.
- **Done when:** two nodes on a Headscale tailnet `ping` each other's `100.x`
      address **through DERP** (confirm via DERP server counters / logs).

## Phase 6 — Direct paths & NAT traversal (the real magic)
Goal: upgrade DERP relays to peer-to-peer UDP.

- [ ] disco ping/pong sweep across candidate endpoints; pick a working direct
      path and switch the peer's send address off DERP.
- [ ] Keepalive + path failure detection; fall back to DERP when a direct path
      dies. Endpoint set changes trigger a `MapRequest` update.
- **Done when:** after the DERP-relayed ping, the path upgrades to direct UDP
      (verify: relay counters stop climbing; latency drops; traffic on the raw
      UDP socket, not DERP).

## Phase 7 — MagicDNS & route acceptance
Goal: names and advertised routes work.

- [ ] `MagicDNS` stub resolver on `100.100.100.100`; answer tailnet names,
      forward the rest per netmap DNS config.
- [ ] Optional "accept routes": install advertised subnet routes via
      `TunDevice`/`WireGuardRoutes`, guarded so nothing silently steals the
      default route.
- **Done when:** `ping <peer-hostname>` resolves and reaches the peer; accepted
      subnet routes carry traffic.

## Phase 8 — Robustness, recovery, GUI polish
Goal: production-quality lifecycle.

- [ ] Reconnect/backoff for control-stream and DERP drops (reuse the daemon's
      backoff pattern); node-key rotation on control request.
- [ ] `RecoverIfCrashed()` rolls back tun/routes/`resolv.conf`/DNS.
- [ ] GUI: AuthURL prompt, tailnet status (self IP, peer count, DERP-vs-direct
      per peer) in the Statistics tab; Deskbar/notifications parity.
- [ ] Docs: fold real setup instructions into the main README; `verify-tunnel`
      extension for the two-node ping check.
- **Done when:** kill -9 the daemon mid-session → restart leaves no stale tun,
      routes or DNS; a full connect/authorize/traffic/disconnect cycle is clean
      from the GUI.

---

## Dependency order

```
0 ─▶ 1 ─▶ 2 ─▶ 3 ─▶ 5 ─▶ 6 ─▶ 7 ─▶ 8
                └▶ 4 ─▶ 6
```

Phase 4 (disco/STUN/NaCl) can proceed in parallel with Phase 5 (DERP) once
Phase 3's netmap exists; both converge at Phase 6.

## Definition of done (level C)

A Haiku box joins a real tailnet through the browser login, appears online to
its peers, reaches them first via DERP and then over a direct hole-punched UDP
path, resolves MagicDNS names, and cleanly tears everything down — with keys
persisted in the keystore and crash recovery leaving the system as found.

## Risks / open questions (resolve as encountered, log in PROGRESS.md)

- **OpenSSL HTTP/2 on Haiku** — if painful, fall back to the HTTP/1.1 framing of
  `ts2021`. Spike in Phase 2.
- **Haiku UDP + multiple local interfaces** — magicsock wants per-interface
  source addresses for STUN; confirm Haiku's socket API exposes what's needed.
- **tun read/write framing** — still the same on-device unknown flagged for the
  WireGuard backend; validate early on real hardware.
- **Headscale feature parity** — some `tailcfg` fields differ; target Headscale
  first, note divergences from the official server.
