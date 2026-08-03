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

## 2026-08-03 — Phase 2: consolidated ControlSession + followup poll hook
- Did: Added `src/backend/tailscale/TSControlSession.{h,cpp}` — one object that
  owns the layered pieces (`ControlClient` → `ControlConn` → `Http2Conn`) in
  dependency order and drives the whole flow: `Connect()` = Noise handshake →
  record stream → HTTP/2 bootstrap (captures the early-payload JSON) → initial
  `Register`. It keeps the HTTP/2 connection open for the Phase-3 MapRequest.
  Extended `Register` with a `followup` argument and added
  `ControlSession::PollAuthorized()` that re-issues the register with
  `Followup: <authURL>` (the server long-polls until the browser login
  completes) — the interactive authorization wait. This is exactly the API the
  backend's worker thread will call.
- Build: **green on-Haiku.** **LIVE test** of the single consolidated call
  against controlplane.tailscale.com: `Connect()` returns HTTP 200 with a real
  `AuthURL https://login.tailscale.com/a/…` and the captured early payload
  `nodeKeyChallenge`. Same end-to-end result as the piecewise flow, now behind
  one call.
- Next: wire `ControlSession` into `TailscaleBackend::Connect` on a worker
  thread (Connect returns immediately; the worker runs handshake→register and
  posts state via `BMessenger(this)`), map states to
  INITIALIZING/CONTROL_HANDSHAKE/AUTHENTICATING, surface the `AuthURL` in the
  `NotifyStateChanged` detail (and open it with `be_roster`), then loop
  `PollAuthorized` until `MachineAuthorized`. After that, Phase 3: MapRequest.

## 2026-08-03 — Phase 2 COMPLETE (core): LIVE node registration + AuthURL
- Did: Added `src/backend/tailscale/TSRegister.{h,cpp}` — builds the JSON
  `tailcfg.RegisterRequest` (Version 144, `NodeKey: nodekey:<hex>`, minimal
  Hostinfo; optional pre-auth key as `Auth.AuthKey`) and parses the
  `RegisterResponse` (AuthURL, MachineAuthorized, NodeKeyExpired, Error) with
  small targeted JSON readers. Over the Noise channel the machine key is already
  authenticated, so the request is plaintext JSON POSTed to `/machine/register`
  with no per-request signature; omitted fields default to zero server-side.
- Build: **green on-Haiku.** **LIVE registration against controlplane.tailscale.com**
  with a fresh machine+node keypair returns **HTTP 200** and a real
  **`AuthURL: https://login.tailscale.com/a/…`**, `MachineAuthorized:false`. That
  is a genuine, working Tailscale login link — opening it in a browser and
  logging in would join this Haiku node to the user's tailnet. The entire
  from-scratch stack (Noise IK handshake → encrypted records → HTTP/2 → HPACK →
  RegisterRequest/Response) is proven end to end against the production Tailscale
  coordination server. This completes the core of Phase 2.
- Next: integration + the followup poll. Wire `TSIdentity` + `ControlClient` +
  `Http2Conn` + `Register` into `TailscaleBackend::Connect` (state machine
  INITIALIZING→CONTROL_HANDSHAKE→AUTHENTICATING), surface the `AuthURL` via
  `NotifyStateChanged` detail so the GUI can open it, and implement the followup
  poll-to-authorized (re-POST with `Followup: <authURL>` until
  `MachineAuthorized`). Then Phase 3: the `MapRequest` long-poll → netmap → WG
  peers.

## 2026-08-03 — Phase 2: HTTP/2 request/response works live over ts2021
- Did: Added `Http2Conn::Request()` — a full request/response exchange on a fresh
  client stream: HPACK-encode the pseudo-headers (`:method/:scheme/:path/
  :authority`) + content-type/length, send HEADERS (+ DATA with END_STREAM),
  then read the response, reassembling HEADERS/CONTINUATION fragments (stripping
  PADDED/PRIORITY), HPACK-decoding `:status` with a connection-lifetime decoder,
  collecting DATA into the body, replenishing stream+connection flow-control
  windows per DATA frame, and answering SETTINGS/PING and bailing on GOAWAY/
  RST_STREAM. Client streams use odd ids.
- Build: **green on-Haiku.** **LIVE end-to-end against controlplane.tailscale.com**:
  `POST /machine/register` returns a well-formed HTTP/2 response —
  `:status 502`, 125-byte body `"backend not found …; reqType=noise-register/
  machine-pubkey; …"`. The 502 is the load balancer's answer for an
  unprovisioned machine key (our body was a placeholder `{}`), but it proves the
  server parsed our HTTP/2 HEADERS+DATA (it identified the request type) and that
  we correctly HPACK-decoded its response status and reassembled its body. The
  whole stack — Noise handshake → encrypted records → HTTP/2 framing → HPACK
  encode/decode → body reassembly — is validated against the production server.
- Next: the real `RegisterRequest`. Build the JSON `tailcfg.RegisterRequest`
  (version, node key = our node public key, machine key, Auth, Hostinfo, and the
  answer to the early-payload `nodeKeyChallenge`), POST it, parse the
  `RegisterResponse` (MachineAuthorized / AuthURL / NodeKeyExpired). Surface the
  `AuthURL` to the daemon → GUI; support a pre-auth key. Then Phase 3 (map).

## 2026-08-03 — Phase 2: HPACK Huffman decode (RFC vectors pass)
- Did: Completed HPACK with Huffman string decoding. Embedded the RFC 7541
  Appendix B table (256 code/length pairs, taken verbatim from Go's
  net/http2/hpack to avoid transcription error) and a prefix-free MSB-first
  decoder: accumulate bits, emit the first symbol whose (code,length) matches
  (safe because the codes are prefix-free), and validate trailing bits as
  all-ones EOS padding. Wired it into `_DecodeString` so Huffman-coded literals
  now decode instead of returning B_NOT_SUPPORTED.
- Build: **green on-Haiku.** Unit tests pass against the official RFC 7541
  vectors: **C.4.1** decodes the Huffman `:authority` to `www.example.com`, and
  **C.6.1** decodes a full Huffman-coded response — `:status 302`,
  `cache-control private`, `date Mon, 21 Oct 2013 20:13:21 GMT`,
  `location https://www.example.com` — exercising letters, digits, spaces,
  commas and punctuation across the alphabet. HPACK is now complete
  (encoder + decoder + Huffman).
- Next: request/response helpers on `Http2Conn` — send HEADERS (HPACK-encoded
  pseudo-headers + content-type/length) + END_HEADERS, then a DATA frame with
  the JSON body and END_STREAM; read the response HEADERS (HPACK-decode
  `:status`) and DATA frames (handle WINDOW_UPDATE/PING, respect stream id 1).
  Then build the JSON `RegisterRequest` and do the first live register against
  controlplane / Headscale, surfacing the `AuthURL`.

## 2026-08-03 — Phase 2: HPACK core (encoder + decoder, non-Huffman)
- Did: Added `src/backend/tailscale/TSHpack.{h,cpp}` — HPACK (RFC 7541) header
  compression. Full 61-entry static table; prefix-integer encode/decode; the four
  header-field representations (indexed, literal-with-incremental-indexing,
  literal-without/never-indexed) and dynamic-table-size updates; a dynamic table
  with RFC size accounting (name+value+32) and eviction. The decoder maintains
  the dynamic table across a block; the encoder stays deliberately simple (static
  name/full-match indexing, raw literal values, no Huffman, no dynamic indexing) —
  all optional for a sender and enough for our requests.
- Build: **green on-Haiku.** Unit test: the RFC 7541 **C.3.1** request example
  decodes exactly to `:method GET, :scheme http, :path /, :authority
  www.example.com` (exercises indexed fields + literal-with-incremental-indexing
  + a dynamic-table insert), and an encoder→decoder round-trip of a realistic
  register header set (`:method POST`, `:path /machine/register`, `:scheme https`,
  `:authority …`, content-type/length) reproduces every header (74 bytes encoded).
- Next: Huffman string decoding (RFC 7541 Appendix B table) — the server
  Huffman-codes its response header strings, so `_DecodeString` currently returns
  B_NOT_SUPPORTED on the H bit; add the decode and validate against RFC C.4
  (`www.example.com` ⇐ `f1e3 c2e5 f23a 6ba0 ab90 f4ff`). Then the request/response
  helpers on `Http2Conn` (HEADERS+DATA out, HEADERS+DATA in) and the first live
  `RegisterRequest`.

## 2026-08-03 — Phase 2: HTTP/2 framing + connection bootstrap (live)
- Did: Added `src/backend/tailscale/TSHttp2.{h,cpp}` — a minimal HTTP/2 client
  over `ControlConn`. It (1) consumes the early payload (magic `\xff\xff\xffTS` +
  BE32 length + JSON `tailcfg.EarlyNoise`, capturing the `nodeKeyChallenge`),
  (2) reads/writes HTTP/2 frames with an internal reassembly buffer (records and
  frames don't align — `_Fill`/`_ReadRaw` refill from `ReadRecord` and compact),
  and (3) runs `Bootstrap()`: sends the client preface + our SETTINGS, ACKs the
  server's SETTINGS and waits for the ACK of ours. Frame header pack/unpack
  (24-bit length, type, flags, 31-bit stream id) and the frame-type/flag enums
  are all in place.
- Build: **green on-Haiku.** **LIVE test against controlplane.tailscale.com**: the
  full HTTP/2 connection comes up over the Noise record stream — early payload
  parsed (`nodeKeyChallenge: chalpub:10183250…`) and the SETTINGS handshake
  completes in both directions (we ACK theirs, they ACK ours). So our frame
  reassembly, framing and preface are accepted by the production server.
- Next: HPACK. Add the static table + an encoder (indexed names + literal values,
  no Huffman needed to send) and a decoder (static/dynamic table + Huffman, needed
  to read the server's response headers). Then a request helper: HEADERS
  (`:method POST`, `:path /machine/register`, `:authority`, `:scheme https`,
  content-type/length) + DATA (JSON `RegisterRequest`), read HEADERS(`:status`) +
  DATA(`RegisterResponse`), and surface the `AuthURL`.

## 2026-08-03 — Phase 2: encrypted record stream verified live (+ protocol recon)
- Did: Added `src/backend/tailscale/TSControlConn.{h,cpp}` — the encrypted record
  layer over the handshaked channel. Seals/opens ts2021 records
  (`[type=4][cipherlen BE16][ciphertext]`, ChaCha20-Poly1305 via OpenSSL EVP, no
  AAD, per-direction counter). Key subtlety captured from the source: the
  transport nonce is **big-endian** (bytes 4..11), unlike the little-endian Noise
  handshake nonce — so it needs its own AEAD, not `WireGuardCrypto`'s. Fixed a
  desync where `ControlClient` dropped the record bytes the server bundles right
  after the 51-byte handshake reply: it now preserves them (`Pending()`), and
  `ControlConn::Init` drains that pushback before the socket. Added a 30s socket
  recv timeout in `TlsClient` so long-poll reads can't hang.
- Build: **green on-Haiku.** **LIVE verification against controlplane.tailscale.com**:
  every record decrypts with a verifying Poly1305 tag. This also reverse-engineered
  the exact post-handshake sequence:
  1. an **early payload** — magic `\xff\xff\xffTS`, a BE32 length, then a JSON
     `tailcfg.EarlyNoise`, e.g. `{"nodeKeyChallenge":"chalpub:d10b405a…"}`;
  2. then the **HTTP/2** stream (server SETTINGS frame observed) — so the control
     RPCs (register/map) are HTTP/2 requests over the Noise record conn.
- Next: a minimal HTTP/2 client over `ControlConn` — connection preface + our
  SETTINGS, HPACK-encode request headers, POST `/machine/register` with the JSON
  `RegisterRequest` (node key, and the response to `nodeKeyChallenge`), read the
  HEADERS/DATA response. On an `AuthURL`, surface it to the daemon → GUI for the
  browser login; support a pre-auth key. HPACK (static table + a tiny dynamic
  table, Huffman optional) is the main new piece.

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
