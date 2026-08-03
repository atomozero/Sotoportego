# Tailscale build — progress log

Living log for the loop-mode build. **Newest entry on top.** Each loop
iteration appends one entry: what phase, what changed, build status, and the
next concrete step so the following iteration can start cold.

Format per entry:

```
## <date> — Phase <n>: <short title>
- Did: <what changed this iteration>
- Build: <make result / n/a>
- Next: <the single next concrete step>
```

---

## 2026-08-03 — Phase 2 MILESTONE: live ts2021 Noise handshake works
- Did: Added `src/backend/tailscale/TSControlClient.{h,cpp}` — the piece that
  ties TLS + framing + Noise into a real control-channel handshake. Pulled the
  HTTP-Upgrade details from Tailscale's control/controlhttp: `POST /ts2021` with
  `Upgrade: tailscale-control-protocol`, `Connection: upgrade`, and the framed
  Noise initiation base64-std in the `X-Tailscale-Handshake` header; the server
  answers `101 Switching Protocols` then writes the framed Noise response on the
  raw connection. `ControlClient::Handshake` fetches `/key`, builds msg1 with the
  version prologue, frames + base64s it, sends the upgrade POST, parses the 101 +
  the 51-byte response record, and runs `NoiseIK::ReadMessage2` — a verifying
  decrypt there proves the whole handshake matched. Added a std base64 encoder.
- Build: **green on-Haiku.** **LIVE TEST PASSED against
  controlplane.tailscale.com**: a fresh machine keypair completes the full Noise
  IK handshake — control key `7d2792f9…`, transport keys derived (tx `d3011bdb…`,
  rx `5729d65c…`). The server's response record decrypted and authenticated, so
  protocol **version 144**, the ts2021 framing, the "Tailscale Control Protocol
  v144" prologue, and the entire `TSNoise` implementation are confirmed
  interoperable with the production Tailscale coordination server. This retires
  the project's single biggest interop risk.
- Next: the post-handshake record stream + registration. Wrap the transport keys
  in a `Conn` that encrypts/decrypts ts2021 record frames (type 4, ChaCha20-
  Poly1305 with per-direction counters), then send the first control message
  `RegisterRequest` (JSON `tailcfg`) with the node key; on a response carrying an
  `AuthURL`, surface it to the daemon → GUI for the browser login, and poll to
  authorized (or use a pre-auth key). Headscale as the first registration target.

## 2026-08-03 — Phase 2: ts2021 framing + control-key parse (spec-exact)
- Did: Pulled the authoritative ts2021 wire format straight from the Tailscale
  source (control/controlbase `messages.go`/`handshake.go`, control/controlhttp,
  tailcfg) rather than guessing, and added `src/backend/tailscale/TSControl.{h,cpp}`
  encoding it exactly:
  * initiation = 5-byte header `[version BE16][type=1][len BE16=96]` + the 96-byte
    Noise msg1; response/record = 3-byte header `[type][len BE16]` + payload
    (48-byte Noise msg2 for the handshake response);
  * the Noise prologue `"Tailscale Control Protocol v<version>"` (mixed into the
    transcript on both sides), default version 144 = `tailcfg.CurrentCapability
    Version` — the server echoes whatever the client advertises, so any supported
    version interoperates; the exact value is validated live next;
  * `ParseControlKey` extracting the `"publicKey":"mkey:<64hex>"` from `/key`.
  Cross-checked the design against the real handshake: protocol name
  `Noise_IK_25519_ChaChaPoly_BLAKE2s`, `h=ck=BLAKE2s(name)`, MixHash(prologue)
  then MixHash(control static), then `e, es, s(enc machine key), ss`, then
  `Split() -> c1=tx, c2=rx` — all identical to the `TSNoise` core already built,
  and the 96/48-byte Noise message sizes line up with `kNoiseMsg1/2Overhead`.
- Build: **green on-Haiku.** Unit test: initiation header serialises to
  `00 90 01 00 60` (version 144, type 1, len 96); record header decodes
  type/len; prologue string exact; and against the *live* `/key` endpoint,
  `ParseControlKey` recovers the control mkey `7d2792f9…` (matches curl).
- Next: the `/ts2021` HTTP-Upgrade handshake — send the framed initiation, read
  the 51-byte response frame, drive `NoiseIK` over the `TSTls` stream to a
  completed control channel (empirically confirm version 144 against the live
  server: a verifying `ReadMessage2` proves the prologue/version matched). Then
  the first in-channel `RegisterRequest` and surfacing the `AuthURL`.

## 2026-08-03 — Phase 2: TLS client + control /key fetch (verified end-to-end)
- Did: Added `src/backend/tailscale/TSTls.{h,cpp}` — a blocking OpenSSL TLS
  client over a Haiku BSD socket (`TlsClient`) plus a one-shot `HttpsGet` helper.
  `Connect()` resolves via `getaddrinfo` (AF_UNSPEC), does the TCP connect, then
  the TLS handshake with SNI and, by default, full certificate verification
  (`SSL_VERIFY_PEER` + default verify paths + `X509_VERIFY_PARAM_set1_host`);
  `SetInsecure(true)` opts out for self-hosted Headscale with an out-of-band
  trusted key. `Read()` maps a peer close (`SSL_ERROR_ZERO_RETURN`, and the
  `SSL_ERROR_SYSCALL`+errno==0 EOF case) to a clean 0 so read-to-end works with
  `Connection: close`. Linked `libssl` in the server Makefile (previously only
  `libcrypto`).
- Build: **green on-Haiku.** End-to-end test (linked against `TSTls.o`): a
  cert-verified `HttpsGet("controlplane.tailscale.com", 443, "/key?v=88")`
  returns HTTP 200 and a body carrying the control server's Noise static public
  key — extracted `mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb3215
  95e2173b`, matching a direct `curl` of the same endpoint. So Haiku's OpenSSL
  finds a CA bundle via the default paths and our verification path works. This
  `mkey` is exactly the `remoteStaticPub` that `NoiseIK::InitInitiator` pins.
- Next: the `ts2021` POST transport that carries the framed Noise handshake.
  Implement the outer wire framing (Tailscale's `initiation`/`response`/`record`
  message headers: type byte + big-endian length, plus the initiation version),
  parse the `/key` JSON for the `mkey`, run `NoiseIK` message 1/2 over the TLS
  stream to `POST <control>/ts2021`, then send the first control `RegisterRequest`
  inside the established Noise channel. Then surface the `AuthURL`. Headscale as
  the first live target.

## 2026-08-03 — Phase 2 (start): Noise IK core for ts2021
- Did: Added `src/backend/tailscale/TSNoise.{h,cpp}` — a generic Noise IK
  handshake (SymmetricState + HandshakeState) for the `Noise_IK_25519_ChaChaPoly_
  BLAKE2s` suite the ts2021 control channel uses. Built entirely on the existing
  `WireGuardCrypto` primitives: BLAKE2s streaming hash for MixHash, `Kdf2` as the
  2-output HKDF for MixKey/Split, `Dh` (X25519) for the DH tokens, and
  `AeadEncrypt/Decrypt` for EncryptAndHash/DecryptAndHash. Key insight that made
  the reuse clean: WireGuard's AEAD nonce is `0x00000000 || counter_le64`, which
  is exactly Noise's nonce, so the Noise message counter feeds straight into the
  WG AEAD. Implemented the full IK flow (pre-message `<- s`, message 1
  `-> e, es, s, ss`, message 2 `<- e, ee, se`) for both initiator and responder,
  plus `Split()` for the directional transport keys and `HandshakeHash()` for
  channel binding. Wired into the server Makefile.
- Build: **green on-Haiku**, no warnings. Unit test (initiator↔responder in one
  process, linked against `TSNoise.o`+`WireGuardCrypto.o`, no network): payloads
  round-trip both directions; both sides derive identical `sendKey`/`recvKey` and
  the same handshake hash; the responder recovers the initiator's static key; a
  single flipped byte in message 1 is rejected by the AEAD. All pass.
- Next: the ts2021 transport layer around this core — (1) the outer wire framing
  Tailscale wraps the Noise messages in (message-type byte + big-endian length,
  and the initiation version header), (2) an OpenSSL TLS client wrapper, and
  (3) the HTTP `POST <control>/ts2021` upgrade that carries the framed Noise
  bytes. Fetch the control server's static key from `<control>/key` first (that
  public key is the `remoteStaticPub` InitInitiator needs). Target Headscale.

## 2026-08-03 — Phase 1: node identity (machine/node/disco keys)
- Did: Added `src/backend/tailscale/TSIdentity.{h,cpp}` — the node's persistent
  identity. Three Curve25519 keypairs (machine / node / disco) generated with the
  existing `wg::DhGenerate` (OpenSSL X25519), reusing the WireGuard backend's
  crypto rather than adding a dependency. Private halves are hex-encoded (so the
  NUL-containing 32 raw bytes survive the string-oriented API) and stored in the
  Haiku keystore via `BPasswordKey`/`BKeyStore`, keyed by
  `sotoportego.tailscale.<profile>.<role>`; public halves are re-derived from the
  private key on every load (via `wg::DhPublic`) and also cached to
  `<identity-dir>/identity` for inspection. `LoadOrCreate(profile)` is idempotent:
  first run mints + stores all three, later runs (and restarts) reload the same
  keys; a corrupt/short keystore entry surfaces `B_BAD_DATA` instead of silently
  re-minting. Added `ToHex`/`FromHex` helpers (reused later for wire formatting).
  Wired into `TailscaleBackend::Connect`: it now establishes identity first and
  logs the public node key (`generated` vs `reused`) before reporting that the
  control channel is still unimplemented. `TSIdentity.cpp` added to the server
  Makefile.
- Build: **green on-Haiku.** Also ran a standalone unit check (linked against the
  compiled `TSIdentity.o`/`WireGuardCrypto.o`, no keystore touched): hex
  round-trip, malformed-hex rejection, and X25519 public-from-private determinism
  all pass — `DhPublic(priv)` reproduces the generation-time public key, which is
  the property cross-launch persistence depends on.
- Next: Phase 2 — control channel. Start with `TSNoise`: the ts2021 Noise IK
  handshake over a byte stream, generalizing `WireGuardCrypto`'s Noise helpers.
  Then an OpenSSL TLS client wrapper and the HTTP transport to `<control>/ts2021`,
  then `RegisterRequest`/`RegisterResponse` with `AuthURL` surfacing. Target a
  local Headscale first.

## 2026-08-03 — Phase 0 complete: TSConfig + on-Haiku build verified
- Did: Added `src/common/TSConfig.{h,cpp}` — the per-profile Tailscale config and
  identity layout. It owns the non-secret control-URL setting (default
  `https://controlplane.tailscale.com`, trailing slash normalised so
  `<url>/ts2021` always composes), an optional *transient* pre-auth key that is
  deliberately never persisted (secret → keystore in Phase 1), and the on-disk
  layout under `~/config/settings/Sotoportego/tailscale/<profile>/` with a
  `_SanitizeComponent` that folds a user-chosen profile name to a single safe
  path component (keeps `[A-Za-z0-9._-]`, strips leading dots) so it can't escape
  the base dir. Load/Save round-trip the config as a flattened BMessage with the
  same atomic temp-file+rename dance as `ProfileStore`. Wired `TSConfig.cpp` into
  the server `Makefile` SRCS.
- Build: **green on-Haiku.** `make -C src/server` compiles TSConfig and links the
  daemon cleanly (this session runs on a real Haiku box — the earlier
  "unverifiable off-Haiku" caveat no longer applies; builds are now verified each
  iteration). No warnings from the new file under `WARNINGS = all`.
- Next: Phase 1 — `TSIdentity` (machine/node/disco Curve25519 keypairs). Generate
  via the existing `wg::DhGenerate`/`DhPublic` (OpenSSL X25519), persist public
  halves under the identity dir and private halves in `BKeyStore`, load-or-create
  on `Connect`. Done when two launches reuse the same machine key.

## 2026-08-03 — Phase 0: backend seam scaffolded
- Did: Wired `TailscaleBackend` into the daemon end to end. Added
  `VPN_BACKEND_TAILSCALE = 3` (`src/common/VPNProfile.h`; archive/unarchive is
  already backend-generic). New `src/backend/tailscale/TailscaleBackend.{h,cpp}`
  — a `VPNBackend` subclass whose `Connect()` cleanly reports
  `B_NOT_SUPPORTED` + an ERROR state for now, with `Disconnect/State/Stats/
  BackendName/LocalIP/RemoteIP/RecoverIfCrashed` stubs. Registered it in
  `SotoportegoServer` (ctor init, `ReadyToRun` construct+observe+recover) and
  taught `_SelectBackend()` a switch that routes `VPN_BACKEND_TAILSCALE` to it.
  GUI backend label switch (`MainWindow.cpp`) now shows "Tailscale". Server
  `Makefile` compiles the new source and adds the include path; CLI/GUI need
  only the enum.
- Build: **not run** — the project builds on Haiku only and this sandbox is not
  Haiku, so `make` can't be invoked. Did a self-review for consistency: the new
  class matches the `VPNBackend`/`WireGuardBackend` patterns, the looper owns
  the handler (no manual delete), and all backend-type switch sites (server
  `_SelectBackend`, GUI label) are updated. Needs an on-Haiku `make` to confirm.
- Next: create `src/common/TSConfig.*` (control URL, optional pre-auth key, and
  the persisted-identity paths under
  `~/config/settings/Sotoportego/tailscale/`), finishing Phase 0, then start
  Phase 1 key generation/persistence.

## 2026-08-03 — Phase 0 kickoff: design, roadmap & scaffolding plan
- Did: Created the `Tailscale` branch and the `design/tailscale/` set — `DESIGN.md`
  (full level-C architecture, module map, crypto inventory, lifecycle, threading),
  `ROADMAP.md` (9 phases 0–8, each with a "Done when" check and a dependency
  graph), and this log. Established that the WireGuard data plane + `WireGuardCrypto`
  are reused, and that the new work is the control plane, magicsock, disco (needs
  a new NaCl-box primitive) and DERP.
- Build: n/a (docs only, no source touched yet).
- Next: Phase 0, first task — add `VPN_BACKEND_TAILSCALE = 3` to
  `src/common/VPNProfile.h` and thread it through `VPNProfile` archive/unarchive
  and the GUI backend-label switch in `src/gui/MainWindow.cpp`.
