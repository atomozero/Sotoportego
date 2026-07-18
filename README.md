# Sotoportego

Native VPN client for Haiku: a privilege-separated background daemon that
owns the VPN lifecycle, with a Haiku-native GUI front-end and a CLI test
client driving it over `BMessage`. OpenVPN is wired in end to end —
`.ovpn` import, real management-interface session, `tun/0` device set-up,
routing fix-up, live throughput and event log.

<p align="center">
  <img src="img/screenshot01.png" alt="Connection tab" width="640" /><br/>
  <em>Connection tab — profiles on the left, server details and Tunnel IP on the right.</em>
</p>

<p align="center">
  <img src="img/screenshot02.png" alt="Statistics tab" width="640" /><br/>
  <em>Statistics tab — session totals and a timestamped event log.</em>
</p>

<p align="center">
  <img src="img/screenshot03.png" alt="Map view" width="640" /><br/>
  <em>Map view — the live VPNGate catalogue with the user's home pin in Italy,
  the connected server highlighted in red, and the arc tracing the tunnel.</em>
</p>

If Sotoportego saves you time, consider supporting development: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-atomozero-yellow?logo=buymeacoffee)](https://buymeacoffee.com/atomozero)


## Features

* **End-to-end OpenVPN** — spawns the `openvpn` binary with
  `--management 127.0.0.1 <port> --management-hold`, talks to its
  management socket from a dedicated reader thread, and posts every
  parsed event back to the daemon's looper.
* **Haiku-specific glue** — scans for the first free `tun/N` slot and
  brings it up before openvpn starts (the Haiku port can't allocate the
  tun device dynamically), then installs the pushed default route via
  the in-tunnel peer so traffic actually flows through the tunnel.
* **Profile management** — import any `.ovpn` file (or a whole folder of
  them at once) through a file panel. The daemon takes its own copy of
  each config under `~/config/settings/Sotoportego/configs/` and persists
  the profile list at `~/config/settings/Sotoportego/profiles`, so a
  profile keeps working even after you move or delete the file you
  imported from; deleting the profile removes its copy. Provider bundles
  such as ProtonVPN's downloadable OpenVPN configs drop straight in.
  Changes are broadcast to every subscribed client.
* **Privilege-separated design** — a background daemon
  (`B_BACKGROUND_APP`, hidden from Deskbar) owns the VPN lifecycle; the
  GUI and CLI are user-facing clients that talk to it over `BMessage`.
* **Native Haiku IPC** — `BApplication` / `BLooper` / `BHandler` all the
  way down; no sockets, no JSON, no daemons-of-daemons.
* **Pluggable backend interface** (`VPNBackend`) — OpenVPN and an in-process
  WireGuard backend both plug into the same seam; the daemon picks one per
  profile. IPSec slots in later.
* **WireGuard backend** — a from-scratch, in-process implementation (Haiku has
  no `wg`/wireguard-go to drive): the Noise IKpsk2 handshake and
  ChaCha20-Poly1305 transport with a bundled BLAKE2s plus OpenSSL's X25519, a
  reader thread multiplexing `tun/N` and UDP, session rekey (~120s) and an
  RFC 6479 anti-replay window, and `AllowedIPs` routing. Validated end to end
  on Haiku against a real WireGuard server: a live session carries traffic
  through the tunnel (confirmed via the exit country), reading raw IPv4 off
  `tun/N`. Import a `.conf` the same way as an `.ovpn`. Both split and full
  tunnels work — a full tunnel (`0.0.0.0/0`) swaps the default route and
  applies the config's DNS (restored on disconnect). IPv6 isn't routed yet.
* **Asynchronous status broadcasts** — `kMsgStatusUpdate` /
  `kMsgStatsUpdate` carry state, detail, both ends of the tunnel and a
  throughput snapshot to every subscribed client.
* **Mose-inspired GUI** — slate header banner with the HVIF brand tile
  and a state-coloured status dot, tabbed `Connection` / `Statistics`
  layout, About dialog with the same brand identity.
* **VPNGate map browser** — a pan/zoom world map (offline coastline
  fallback + OSM raster tiles via `TileCache`) plotting every public
  VPNGate server as a clickable pin. The daemon-side `VPNGateFetcher`
  pulls the catalogue from vpngate.net, base64-decodes each `.ovpn`
  body and geocodes hosts to a country centroid; the GUI overlays a
  "you are here" pin (from `ip-api.com`) and traces a connection arc
  to the active server. The side panel shows host / country / log
  policy and three colour-coded `MetricPill`s for ping / score /
  sessions, so a usable server is one glance away. Click Connect and
  the daemon stages the `.ovpn` under
  `~/config/cache/Sotoportego/` and reuses the normal OpenVPN flow.
* **Credentials prompt with optional remember** — modal
  `CredentialsWindow` before every Connect, with a "Remember password"
  checkbox; tick it once and the next Connect for that profile skips
  the prompt entirely, pulling the stored secret from the Haiku
  keystore (`BKeyStore` / `BPasswordKey`). Unticked credentials are
  transient and never reach disk. A *Connection → Forget saved
  password* menu item drops a stored entry on demand, and the same
  cleanup runs automatically if `AUTH_FAILED` lands while we were
  using a stored secret, so a server-side password change can't loop
  forever.
* **Desktop notifications** — `BNotification` toasts on Connect /
  Disconnect / Error so the GUI doesn't have to be in the foreground.
  The Connect notification then updates itself with the *apparent
  country* once a background geo-lookup (HTTP through the tunnel)
  returns; the same value is broadcast to subscribed clients so the
  GUI's status bar shows it alongside the connection state.
* **Auto-reconnect with backoff** — if a session drops on its own (the
  openvpn process exits without a user Disconnect), the daemon retries
  the same profile on an exponential backoff (5, 10, 20, 40, 60s, up to
  five attempts) and surfaces a live *Reconnecting — retry in Ns* countdown
  in the header. A successful reconnect resets the budget; a user
  Disconnect cancels it; an authentication failure is never retried, so a
  bad password can't loop.
* **CLI test client** — `sotoportego_cli` proves the IPC + backend seams
  with a one-shot connect / linger / disconnect round-trip.
* **Deskbar replicant** — a small "world" glyph with an open/closed
  padlock overlay sits next to the Deskbar clock, redrawing whenever
  the session state changes. A single click pops a menu listing every
  imported profile so you can connect to your preferred server in two
  clicks; the same menu carries Disconnect, *Open Sotoportego…* and
  *Remove from Deskbar*. The replicant persists across reboots: it is
  archived through `BArchivable`, and Deskbar reinstantiates it from
  the GUI binary on next login via the standard add-on path.
* **Built-in event log** — every state transition is appended to the
  Statistics tab with a timestamp, so failures are never silent.


## Requirements

* **Haiku R1/beta5 or newer** with the standard `makefile-engine` at
  `/system/develop/etc/makefile-engine`.
* **OpenVPN** from HaikuDepot — install once:

  ```
  pkgman install openvpn
  ```

* The kernel **tunnel** network add-on, shipped with Haiku at
  `/system/add-ons/kernel/network/devices/tunnel`. The daemon publishes
  the actual device with `ifconfig tun/N up` on every Connect (`N`
  being the first slot free at that moment), so no manual setup is
  required.


## Build

The project builds and runs on Haiku only. Each binary has its own
makefile under `src/`; the top-level `Makefile` recurses into them.

```
make                       # builds everything: daemon + CLI + GUI
make -C src/server         # builds just the daemon
make -C src/cli            # builds just the CLI client
make -C src/gui            # builds just the GUI client
make clean                 # removes all build artifacts
```

The produced binaries land in each subdirectory's
`objects.x86_64-cc13-release/` folder.

To bundle them into a Haiku package, run `./scripts/make-hpkg.sh` — it
builds everything and writes `dist/sotoportego-<version>-x86_64.hpkg`
(the three binaries under `apps/Sotoportego/`). Install it with
`pkgman install dist/sotoportego-*.hpkg`, or drop the `.hpkg` into
`~/config/packages/`.


## Run

### GUI

```
./src/gui/objects.x86_64-cc13-release/Sotoportego
```

The GUI launches the daemon automatically via `be_roster`. From there:

1. Click **+** to import one or more `.ovpn` profiles. The daemon parses
   `remote`, `proto`, `port` and `auth-user-pass`, takes its own copy of
   the config under `~/config/settings/Sotoportego/configs/`, and stores
   the profile — so you can delete the file you imported from afterwards.
   See *Import from ProtonVPN* below for provider configs.
2. Select a profile in the list. The **Server** box on the right shows
   the host, backend, protocol and (after Connect) the tunnel-assigned
   **Tunnel IP**.
3. Click **Connect**, fill in the credentials prompt (tick **Remember
   password** if you don't want to re-type them next time), watch the
   status dot in the header walk through *Connecting → Authenticating
   → Connected*. The bottom status bar gains the apparent country a
   second or two later; the **Statistics** tab keeps a live event log
   and download/upload counters.
4. **Disconnect** asks openvpn to terminate via the management socket,
   removes the routes we installed and deletes the `tun/N` interface
   we brought up, so the routing table is left exactly the way it was
   found.

You can also drop the **Tools → Install Deskbar icon** entry into your
Deskbar from the same window. The replicant subscribes to the daemon
on its own and stays live whether or not the main window is open; a
left click on it shows your profile list, lets you connect with two
clicks, and offers Disconnect / *Open Sotoportego…* / *Remove from
Deskbar* below. The icon comes back automatically after a reboot.

### Import from ProtonVPN (and other providers)

Sotoportego imports the standard OpenVPN config files that ProtonVPN —
and most commercial providers — let you download, so there's no separate
provider account to wire in.

1. On the ProtonVPN dashboard open **Downloads → OpenVPN configuration
   files** and download the servers you want (per-country or per-server,
   UDP or TCP). You can grab a whole batch at once.
2. In Sotoportego click **+** and select one file or many together. Each
   becomes a profile, and because the daemon keeps its own copy you can
   delete the downloads afterwards.
3. Click **Connect** and enter the **OpenVPN / IKEv2 credentials** shown
   on the ProtonVPN dashboard (under *Account*) — **not** your Proton
   login. Tick **Remember password** to skip the prompt next time.

Provider configs often list several `remote` lines for fail-over:
openvpn uses them all and the profile is named after the first. The
crypto (`<ca>`, `<tls-crypt>`, cipher) is handled by openvpn itself from
the config, so any suite your Haiku `openvpn` build supports will
connect.

### Browse servers on a map

**Tools → Browse servers on map** (or the same item from the Deskbar
replicant) opens `VPNMapWindow`. The daemon fetches the VPNGate
catalogue on first request and broadcasts it via `kMsgVPNGateList`;
each entry becomes a yellow pin on the map, geocoded to its country
centroid. A blue dot marks your current real-world location (resolved
from your public IP via `ip-api.com`); during an active session a
colored arc traces the tunnel from the blue dot to the chosen server.

The toolbar above the map mirrors the **Map** menu (Zoom in / Zoom
out / Fit to pins / Toggle tiles / Refresh catalogue). The side
panel on the right shows the selected pin's host, country, log
policy and three colour-coded badges:

* **Ping** — green under 50 ms, amber under 150 ms, otherwise red.
* **Score** — vpngate's bandwidth-ish metric; green above 100k,
  amber above 30k.
* **Sessions** — current users; green at 30 or fewer, amber up to
  100, red beyond.

Because the VPNGate catalogue is Japan-heavy, many country centroids
land on the same spot at low zoom. Pins that share a screen position
collapse into a single marker whose badge shows how many servers it
covers; zoom in and they spread back into individual pins. Click a
cluster and the side panel lists every server under it (host / ping /
score) so you can pick one and Connect without zooming in.

Click **Connect** with a pin selected, fill in the credentials prompt
(vpngate's public servers usually accept `vpn` / `vpn`), and the
daemon stages the `.ovpn` body cached on the pin and feeds it through
the same OpenVPN flow as a manually-imported profile.

### Daemon (manual)

You can start the daemon by hand to watch its log — useful while
diagnosing a `.ovpn` that misbehaves:

```
./src/server/objects.x86_64-cc13-release/sotoportego_server
```

Every line that openvpn writes over its management socket is echoed as
`[OpenVPN] <message>`, so any `AUTH_FAILED`, `route` error or `FATAL`
shows up immediately next to the daemon's own state-machine events.

### CLI

```
./src/cli/objects.x86_64-cc13-release/sotoportego_cli
```

`sotoportego_cli` launches the daemon if needed, subscribes for
updates, connects with a small built-in demo profile, prints every
state and stats update, then disconnects and exits. It's the simplest
proof that the IPC and backend seams work end to end without the GUI.


## Verify the tunnel actually carries traffic

`scripts/verify-tunnel.sh` is a shell check that asserts, in order,
that the tunnel is up *and* outbound traffic is going through it. Run
it from another terminal while the GUI shows **Connected**:

```
./scripts/verify-tunnel.sh
```

It walks through:

1. A `tun/N` interface exists and has an IPv4 address.
2. Haiku's `route` table puts the default route on that `tun/N`
   (matched on `0.0.0.0 0.0.0.0 … tun/N` — Haiku doesn't spell the
   default route as the word "default").
3. `https://api.ipify.org` reports an external IP **different** from
   the local wifi IP — this is the only step that proves outbound
   HTTPS is being carried by the tunnel rather than leaking onto the
   physical link.
4. Prints the routing table so the VPN server's own IP can be
   eyeballed: it must still leave through the original gateway, not
   `tun/N`, otherwise the carrier loops through its own tunnel.

The script exits non-zero on the first failure, so re-running it
after **Disconnect** should fail at step 1: the cleanest way to
confirm the teardown left the routing table back the way it was.


## Layout

```
src/common/    Shared types and wire protocol (VPNState, VPNStats,
               VPNProfile, VPNProtocol.h, OpenVPNConfigParser)
src/backend/   Backend seam: VPNBackend interface, real OpenVPNBackend
               (process + management socket + reader thread), and
               OpenVPNManagement (the management-interface parser)
src/server/    The daemon (a BApplication / BLooper), ProfileStore
               (persistent profiles), GeoLookup (background HTTP
               worker behind the connect notifications and the map's
               self pin), VPNGateFetcher (VPNGate catalogue
               downloader) and CountryCentroids (country-name ->
               centroid lat/lon table the catalogue geocoder uses)
src/cli/       sotoportego_cli — the test client
src/gui/       Sotoportego — the native GUI client. Main window
               stack: HeaderView, MainWindow, CredentialsWindow,
               About, DeskbarIcon replicant, brand HVIF. Map
               browser stack: VPNMapWindow (toolbar + side panel),
               MapView (pan/zoom world map with server pins +
               self pin + connection arc), MetricPill (colour-
               coded ping/score/sessions badges), TileCache (OSM
               tile fetcher + on-disk cache) and CoastlineData
               (offline coastlines for the tiles-disabled mode).
scripts/       verify-tunnel.sh — shell check that the tunnel is
               up *and* actually carrying outbound traffic
```

| Binary               | MIME signature                              |
| -------------------- | ------------------------------------------- |
| `sotoportego_server` | `application/x-vnd.VePro-SotoportegoServer` |
| `sotoportego_cli`    | `application/x-vnd.VePro-SotoportegoCLI`    |
| `Sotoportego`        | `application/x-vnd.VePro-Sotoportego`       |


## Architecture notes

* **The daemon is the single source of truth.** Clients can come and go
  (the GUI can be closed without dropping the session); the daemon keeps
  the openvpn child alive, the management socket open and the in-memory
  state authoritative. Reconnecting clients get the current snapshot
  plus the profile list as part of `kMsgSubscribe`.
* **All state mutations happen on the looper thread.** The reader thread
  reads bytes off the management socket, hands them to
  `OpenVPNManagement::Feed()`, and posts each parsed event back via
  `BMessenger(this)` so the backend's `MessageReceived` is the only
  place state changes — no locks, no surprises.
* **Routing fix-up is ours.** The Haiku patches to openvpn 2.6.13
  hardcode the underlying physical interface in every route command, so
  the pushed `redirect-gateway def1` ends up on wifi/ethernet instead of
  the tunnel. We pass `--route-noexec`, scan `ROUTE_GATEWAY` and
  `PUSH_REPLY` out of the log stream, and install three things ourselves
  once CONNECTED arrives: the VPN server's IP pinned to the original
  gateway (so the openvpn carrier doesn't loop through its own tunnel),
  the original default route removed, and a new default route via the
  tunnel peer on `tun/N`. Both the routes and the `tun/N` interface
  itself are torn back down on Disconnect.
* **Notifications go through the tunnel.** The geo-lookup behind the
  Connect notification fires *after* CONNECTED, so the HTTP request to
  ip-api.com travels through `tun/0` and reports the country we now
  appear to come from, not the carrier's. It's a 4-second worker
  thread with a hard timeout; if the egress blocks port 80 the
  original "Connected to ..." toast stays put.
* **`docs/` and `tests/` are intentionally not part of the repo.** They
  live on disk for the author's workflow but the tracked tree is the
  shipping artefact.


## Roadmap

* IPv6 routing fix-up (both backends are IPv4-only today).
* IPSec.


## Be careful

> **Developer's Note**: This software may contain traces of peanuts and
> LLM. It has been developed with passion for the Haiku platform.


## Support

If you find this project useful, you can buy me a coffee: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-atomozero-yellow?logo=buymeacoffee)](https://buymeacoffee.com/atomozero)
