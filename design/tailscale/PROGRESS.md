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

## 2026-08-04 — Phase 3/5 bridge: TSPeerSet (netmap → data-plane peers)
- Did: Added `src/backend/tailscale/TSPeerSet.{h,cpp}` — the live peer set driven
  by the network map. `Update(TSNetmap)` diffs each MapResponse into a set of
  `ManagedPeer`s keyed by node-key hex: new peers are added (decoding the 32-byte
  node key into their `WGPeer`), departed peers removed, and existing peers'
  reachability (endpoints, AllowedIPs, DERP-home, online, hostname) refreshed
  in place while keeping their `WGPeer` and any negotiated transport keys. This
  is the glue between the parsed netmap (Phase 3) and the per-peer transport
  (`WGPeer`).
- Build: **green on-Haiku.** Unit test across two successive netmaps: round 1 adds
  peers A+B; round 2 (A with a new endpoint/DERP/offline, B gone, C new) reports
  +1/−1/~1, leaves A refreshed in place (endpoint `9.9.9.9:55555`, DERP 5,
  offline), drops B, adds C, and decodes C's 32-byte WireGuard node key.
- Next: the magicsock reader thread that ties it together — bring up a `tun/N`
  with `TSNetmap::SelfIPv4()`, run the per-peer Noise IKpsk2 handshake to fill
  each `WGPeer`'s transport keys, then forward tun↔peer packets choosing the send
  path (direct UDP once a disco pong lands, else via the `DerpClient`).

## 2026-08-04 — Phase 3/5 bridge: WGPeer transport unit (round-trip verified)
- Did: Added `src/backend/tailscale/WGPeer.{h,cpp}` — one WireGuard peer's
  data-plane transport, factored out of WireGuardBackend so the Tailscale backend
  can run N peers keyed by node key. It owns the per-direction transport keys, the
  send counter, the peer's receiver index and an RFC 6479 anti-replay window, and
  frames plaintext IP packets into WireGuard type-4 transport messages
  (`[4][000][recvIndex LE][counter LE][ChaCha20-Poly1305(padded)]`) and back,
  stripping the 16-byte padding via the IP header length. `SetTransport` installs
  the keys a completed handshake produced; the send path (direct vs. DERP) stays
  magicsock's concern.
- Build: **green on-Haiku.** Unit test (symmetric keys, loopback): a 20-byte IPv4
  packet encapsulates and decapsulates back byte-for-byte with the padding
  stripped; the receiver index serialises little-endian; anti-replay rejects a
  re-submitted counter; a 0-length keepalive round-trips to length 0; and a
  flipped ciphertext byte fails to authenticate.
- Next: give `WGPeer` the per-peer Noise IKpsk2 handshake + rekey (shared with
  WireGuardBackend), then the magicsock reader thread wiring: dispatch inbound WG
  datagrams to the matching peer's `Decapsulate`, send via the chosen path, and
  bring up a `tun/N` slot with `TSNetmap::SelfIPv4()` so packets actually flow.

## 2026-08-04 — Phase 5: magicsock STUN sweep (live reflexive endpoint)
- Did: Added `MagicSock::DiscoverEndpoint` — the STUN sweep run over the *shared*
  magicsock UDP socket (not a throwaway one), so the reflexive ip:port it learns
  is the mapping for the exact port peers reach us on. It sends a `TSStun` binding
  request, then reads datagrams off the socket, skipping anything that isn't a
  STUN reply (`Classify` demux) until the matching binding-success lands, with a
  few retries bounded by the socket's 1s recv timeout.
- Build: **green on-Haiku.** **LIVE test**: a magicsock bound to an ephemeral port
  discovered this box's reflexive public endpoint (`151.34.38.188:46285`) via a
  public STUN server over the shared socket — magicsock + STUN + the classifier
  working together on the real network. This endpoint is what magicsock reports to
  control for hole-punching.
- Next: the magicsock reader thread that dispatches by `Classify` (STUN → endpoint
  update, disco → `TSDisco` ping/pong handling, WireGuard → transport), the disco
  probe of candidate endpoints, and per-peer direct-vs-DERP path selection; then
  the `WGPeer` bridge to carry real packets.

## 2026-08-04 — Phase 5: magicsock UDP socket + inbound classifier
- Did: Added `src/backend/tailscale/MagicSock.{h,cpp}` — the single UDP socket
  that carries all peer traffic. Bind (ephemeral or fixed port, with a 1s recv
  timeout so a reader loop can poll a stop flag), `SendTo`/`Recv`, and the
  inbound `Classify` that demuxes each datagram by its leading bytes: the 6-byte
  disco magic `TS💬` → PKT_DISCO; the STUN magic cookie at offset 4 with the top
  two bits of byte 0 clear → PKT_STUN; everything else (WireGuard transport, type
  byte 1..4) → PKT_WIREGUARD.
- Build: **green on-Haiku.** Unit test: the classifier tags crafted disco / STUN /
  WireGuard datagrams correctly, and a loopback round-trip (bind an ephemeral
  port, sendto ourselves, recv) demuxes all three kinds — the real socket path
  works, not just the pure function.
- Next: the magicsock reader thread + endpoint/probe machinery — run the STUN
  sweep over this socket (send `TSStun` binding requests to DERP STUN, collect
  the reflexive endpoints), drive `TSDisco` ping/pong to candidate endpoints, and
  maintain each peer's send path (a direct `sockaddr` once a disco pong returns,
  else via the `DerpClient`). Then bridge to the WireGuard transport (`WGPeer`).

## 2026-08-04 — Phase 5 (start): DERP client handshake works live
- Did: Added `src/backend/tailscale/TSDerp.{h,cpp}` — a DERP relay client. Pulled
  the wire protocol from tailscale/derp + derphttp: an HTTP `GET /derp` upgrade
  (`Upgrade: DERP`, expect 101), then binary frames `[type 1B][len uint32 BE]
  [payload]`. Implemented the frame codec (buffered `ReadFrame`/`WriteFrame`),
  the handshake (parse frameServerKey = magic `DERP🔑` + 32-byte server key; send
  frameClientInfo = our node pub + nonce + `NaClBox`-sealed JSON to the server
  key), and `SendPacket(dstKey, wg)` / `RecvPacket(srcKey, wg)` with PING→PONG.
- Build: **green on-Haiku.** **LIVE handshake against derp1.tailscale.com**: the
  `/derp` upgrade returns 101, we parse the real server key
  (`69dcb903…4b817171`), and our boxed clientInfo is accepted (the relay keeps
  the connection open). So the upgrade, frame codec and NaCl-boxed clientInfo all
  interoperate with a production DERP relay.
- Next: `MagicSock` — one UDP socket that demuxes inbound datagrams by first
  bytes into STUN responses, disco messages (magic `TS💬`) and WireGuard
  transport packets, drives the STUN endpoint sweep and disco probing, and
  chooses each peer's send path (direct `sockaddr` vs. via this DERP client).
  Then bridge it to the WireGuard transport (the `WGPeer` factor-out).

## 2026-08-04 — Phase 4 complete: disco protocol (Ping/Pong seal+open)
- Did: Added `src/backend/tailscale/TSDisco.{h,cpp}` — the disco packet framing
  and message codecs. Pulled the exact wire format from tailscale/disco: a packet
  is `Magic("TS💬" = 54 53 f0 9f 92 ac) + senderDiscoPub(32) + nonce(24) +
  NaClBox(payload)`; the plaintext is a 2-byte header (type + version) then
  fields. Implemented Ping (12-byte TxID + optional 32-byte node key) and Pong
  (TxID + the observed source ip:port, encoded as Tailscale's 16-byte v4-mapped
  IPv6 + 2-byte port), plus `DiscoSeal`/`DiscoOpen` which box to/from the disco
  keys with a fresh random nonce and check the magic.
- Build: **green on-Haiku.** Unit test: a Ping (with node key) and a Pong
  (`151.34.38.188:46089`) each seal into a full packet and open back with the
  right sender key, type, TxID and fields; the v4-mapped ip:port round-trips; and
  a single flipped ciphertext byte fails to open. **Phase 4 primitives are now
  complete** — NaCl box (canonical vectors), STUN (live public endpoint) and disco
  (round-trip) all verified.
- Next: Phase 5 — the DERP client. One long-lived framed TLS connection to a
  home-region relay (host from the netmap's DERPMap), speaking DERP's binary
  frame protocol (send our node key, then SendPacket(dstKey, wgBytes) /
  RecvPacket(srcKey, wgBytes)). This gives first-packet connectivity before the
  disco direct-path upgrade. Also start `MagicSock` (one UDP socket demuxing
  STUN/disco/WireGuard).

## 2026-08-04 — Phase 4: STUN client (live public endpoint discovered)
- Did: Added `src/backend/tailscale/TSStun.{h,cpp}` — a minimal RFC 5389 STUN
  binding client. `StunBuildRequest` emits a 20-byte binding request with a
  random transaction id; `StunParseResponse` validates the binding-success
  response (magic cookie + tx id) and decodes XOR-MAPPED-ADDRESS (with a
  MAPPED-ADDRESS fallback), un-XORing the IPv4 address/port against the magic
  cookie; `StunQuery` does the UDP round-trip (getaddrinfo + a 5s recv timeout).
- Build: **green on-Haiku.** Two-part test: offline, a crafted XOR-MAPPED-ADDRESS
  response decodes to `1.2.3.4:4660`; **live**, a binding request to a public STUN
  server reflected this box's real public endpoint (`151.34.38.188:46089`). That
  reflexive `ip:port` is exactly what magicsock reports to control as one of our
  endpoints for peers to hole-punch toward.
- Next: `TSDisco` — encode/decode the disco protocol messages (CallMeMaybe,
  Ping, Pong) that magicsock exchanges to find a working direct path. They carry
  the `TS💬` magic + the sender's disco public key and are NaCl-boxed to the
  peer's disco key (now that `NaClBox` exists), unit-testable by boxing a
  ping/pong to ourselves and checking the round-trip + magic header.

## 2026-08-04 — Phase 4 (start): NaCl box for disco (canonical vectors pass)
- Did: Added `src/backend/tailscale/NaClBox.{h,cpp}` — NaCl "box" authenticated
  public-key encryption (Curve25519 + XSalsa20-Poly1305), the one primitive the
  Noise/WireGuard reuse couldn't cover and which Tailscale's `disco` protocol
  needs. Ported the Salsa20 core, HSalsa20, XSalsa20 stream and Poly1305 MAC from
  public-domain TweetNaCl; the Curve25519 scalar mult delegates to OpenSSL's
  X25519 (`wg::Dh`, identical to `crypto_scalarmult`). Clean API: `BoxBeforeNm`
  (shared key), `BoxSeal/BoxOpen` (one-shot with peer key), and the
  precomputed-key variants — internally handling TweetNaCl's zero-byte padding
  convention.
- Build: **green on-Haiku.** Unit test against the **canonical NaCl box vectors**:
  `BoxBeforeNm(alicesk, bobpk)` equals the published firstkey
  `1b275564…44f68389`; sealing the 131-byte reference message reproduces the
  reference ciphertext (tag+ct) byte-for-byte; `BoxOpen` round-trips; and a single
  flipped ciphertext byte fails authentication.
- Next: Phase 4 continues — `STUN` (a minimal binding request/response to learn
  our public ip:port per interface) and `TSDisco` (encode/decode the disco
  ping/pong messages, which are NaCl-boxed with the disco key and carry the magic
  `TS`+0x9c... prefix). Both are small and unit-testable offline.

## 2026-08-03 — Phase 3: DERPMap + DNSConfig parsing (netmap parse complete)
- Did: Extended `TSNetmap` to parse the `DERPMap` (its `Regions` map keyed by
  region-id strings → each region's code + `Nodes` array of relay servers with
  HostName/IPv4/IPv6/DERPPort) and the `DNSConfig` (modern `Resolvers:[{Addr}]`
  and legacy `Nameservers:[…]`, plus `Domains`). Added `DerpNode`/`DerpRegion`/
  `DnsConfig` structs, `DerpRegions()`, `Dns()` and a `DerpRegionById()` lookup
  so a peer's home-region relay host can be resolved for DERP fallback.
- Build: **green on-Haiku.** Unit test against an extended fixture: two DERP
  regions (nyc with two relay nodes, sfo with one) with correct
  hostnames/IPv4/port, and DNS resolver `100.100.100.100` + domain
  `tail9f3c.ts.net`. The netmap parser now covers everything the data plane and
  MagicDNS need.
- Next: the data-plane bridge. Factor `WireGuardBackend`'s transport core into a
  reusable per-peer `WGPeer` (Noise IK handshake + type-4 transport + rekey +
  RFC 6479 anti-replay), so the Tailscale backend can run N peers keyed by node
  key, each with a send path chosen by magicsock (direct `sockaddr` or via DERP)
  instead of a single fixed endpoint. Assign `TSNetmap::SelfIPv4()` to a tun slot.

## 2026-08-03 — Phase 3: netmap parser (TSJson + TSNetmap)
- Did: Added `src/backend/tailscale/TSJson.{h,cpp}` — a small recursive-descent
  JSON DOM parser (objects, arrays, strings with the standard escapes + \uXXXX
  incl. surrogate pairs → UTF-8, numbers, bools, null), since a MapResponse is
  too deeply nested for flat string scanning. Added `TSNetmap.{h,cpp}` which walks
  that tree to extract the data-plane essentials: our own tailnet addresses
  (`Node.Addresses`, with `SelfIPv4()` for the tun) and each peer's node key,
  disco key, AllowedIPs, direct-path Endpoints, home DERP region (decoding
  Tailscale's `127.3.3.40:<region>` form), online flag and hostname.
- Build: **green on-Haiku.** Unit test against a synthetic MapResponse fixture:
  self `100.64.1.5` (+ IPv6), two peers with correct keys, DERP regions (2, 10),
  AllowedIPs, endpoints and online flags — and a `à`-escaped hostname
  correctly decoded to UTF-8 (`peer-làptop`), exercising nested objects/arrays,
  escapes and unicode.
- Next: extend the parser for `DNSConfig` (Nameservers/Domains) and the full
  `DERPMap` (region → nodes → host:port), then start the data-plane bridge:
  factor `WireGuardBackend`'s transport core into a reusable per-peer `WGPeer`
  (handshake/transport/rekey/anti-replay) so the Tailscale backend can run N
  peers from the netmap, and assign `SelfIPv4()` to a tun slot.

## 2026-08-03 — Phase 3: MapRequest + streamed response de-framer
- Did: Added `src/backend/tailscale/TSMap.{h,cpp}` — `MapStream`, which builds the
  JSON `MapRequest` (Version, NodeKey, `Stream:true`, `OmitPeers:false`, empty
  Endpoints, minimal Hostinfo; Compress omitted → plain JSON), POSTs it to
  `/machine/map` via the streaming `Http2Conn::BeginRequest`, and de-frames the
  response with `ReadMessage`: each `MapResponse` is a 4-byte little-endian
  length prefix + that many JSON bytes, buffered across HTTP/2 DATA frames.
- Build: **green on-Haiku.** Live check against controlplane.tailscale.com: after
  a fresh register (HTTP 200 + AuthURL), the `POST /machine/map` is sent and the
  server responds with headers — **HTTP :status 404**. That's the coordination
  LB's answer for an *unauthorized* node (no map backend until the node is logged
  in), the same gating the unprovisioned register path shows. So the map request
  build + HTTP/2 streaming transport are exercised end to end; a *real* netmap
  needs an authorized node — reached either after interactive browser login or,
  per the design's primary dev target, against a local **Headscale with a pre-auth
  key** (non-interactive). That is the right place to validate live peer data.
- Next: the `TSNetmap` JSON parser — a small recursive JSON reader + extraction
  of the fields we need (self `Node.Addresses` = our 100.x, and per-peer
  `Key`/`DiscoKey`/`Endpoints`/`DERP`/`AllowedIPs`; `DNSConfig`; `DERPMap`),
  unit-tested against a captured/synthetic `MapResponse` fixture (no authorized
  node required). Then wire the netmap into the backend and assign the tun IP.

## 2026-08-03 — Phase 3 (start): streaming HTTP/2 request (for the map long-poll)
- Did: The `MapRequest` is an HTTP/2 long-poll whose response streams many
  `MapResponse` messages, so the read-to-END_STREAM `Request()` can't drive it.
  Split `Http2Conn` into a streaming API: `BeginRequest()` sends HEADERS(+DATA)
  and reads up to and including the response HEADERS (decoding `:status`) without
  consuming the body; `ReadBody()` then returns one DATA frame's payload per call
  (stripping padding, replenishing stream+connection flow-control windows,
  answering SETTINGS/PING, honoring END_STREAM → `*outLen == 0`). Reimplemented
  `Request()` as `BeginRequest` + a `ReadBody` loop, so the one-shot and
  streaming paths share code.
- Build: **green on-Haiku.** Regression-checked live against
  controlplane.tailscale.com: registration through the refactored `Request()`
  still returns HTTP 200 + a real AuthURL, so `BeginRequest`/`ReadBody` are
  correct.
- Next: build the JSON `tailcfg.MapRequest` (Version, NodeKey, Endpoints, Stream:
  true, Compress: "" for plain JSON, Hostinfo), `BeginRequest` POST `/machine/map`,
  then read the response body as a sequence of 4-byte little-endian length-prefixed
  `MapResponse` JSON messages via `ReadBody` (buffering across DATA frames), and
  parse `TSNetmap` (self 100.x address, peers: node key, DiscoKey, Endpoints,
  DERP-home, AllowedIPs; DNSConfig; DERPMap).

## 2026-08-03 — Phase 2: TailscaleBackend drives the control flow (worker thread)
- Did: Wired `ControlSession` into `TailscaleBackend`. `Connect()` now snapshots
  the control host (profile `fServer`, default controlplane.tailscale.com), the
  tailnet hostname and any auth key, loads the identity, sets CONNECTING and
  spawns a `tailscale-control` worker (returns immediately). The worker runs
  `ControlSession::Connect` (handshake → HTTP/2 → register) and posts private
  messages back via `BMessenger(this)`: `kMsgTsAuthURL` → looper sets
  AUTHENTICATING with the AuthURL as the state detail (so the GUI can show/open
  it), then it long-polls `PollAuthorized` until authorized. `Disconnect()` sets
  a stop flag the worker checks between polls (bounded by the 30s socket
  timeout); the worker's final message settles the state. On authorization it
  currently reports a clear ERROR ("Authorized. Data plane … not implemented yet
  — Phase 3+") rather than a false CONNECTED, since the WG data plane isn't built.
- Build: **green on-Haiku.** The control flow it drives is the same
  `ControlSession` already proven live against controlplane.tailscale.com
  (HTTP 200 + real AuthURL). An automated in-process backend test
  (BLooper + observer + `Connect`) could not run to completion here: it blocks in
  `TSIdentity::LoadOrCreate` on the Haiku keystore's keyring-unlock prompt, which
  a headless test can't answer — an environment limit (same one flagged in
  Phase 1), not a code fault. Full backend end-to-end (select a Tailscale profile
  → Connect → AuthURL in the header → browser login) is verified interactively
  from the GUI, where the keyring is unlocked.
- Next: Phase 3 — the `MapRequest` long-poll. POST `/machine/map` over the open
  `Http2Conn`, stream `MapResponse`s, parse `TSNetmap` (self 100.x, peers: node
  keys, endpoints, DERP-home, AllowedIPs, DNS, DERPMap), and start assigning the
  tun IP. Also: a small GUI touch to make the AuthURL clickable/auto-open.

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
