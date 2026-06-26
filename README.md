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
* **Profile management** — import any `.ovpn` file through a file panel.
  The daemon persists the list at
  `~/config/settings/Sotoportego/profiles` and broadcasts changes to
  every subscribed client.
* **Privilege-separated design** — a background daemon
  (`B_BACKGROUND_APP`, hidden from Deskbar) owns the VPN lifecycle; the
  GUI and CLI are user-facing clients that talk to it over `BMessage`.
* **Native Haiku IPC** — `BApplication` / `BLooper` / `BHandler` all the
  way down; no sockets, no JSON, no daemons-of-daemons.
* **Pluggable backend interface** (`VPNBackend`) — OpenVPN ships today;
  WireGuard and IPSec slot into the same seam later.
* **Asynchronous status broadcasts** — `kMsgStatusUpdate` /
  `kMsgStatsUpdate` carry state, detail, both ends of the tunnel and a
  throughput snapshot to every subscribed client.
* **Mose-inspired GUI** — slate header banner with the HVIF brand tile
  and a state-coloured status dot, tabbed `Connection` / `Statistics`
  layout, About dialog with the same brand identity.
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
* **CLI test client** — `sotoportego_cli` proves the IPC + backend seams
  with a one-shot connect / linger / disconnect round-trip.
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


## Run

### GUI

```
./src/gui/objects.x86_64-cc13-release/Sotoportego
```

The GUI launches the daemon automatically via `be_roster`. From there:

1. Click **+** to import an `.ovpn` profile. The daemon parses
   `remote`, `proto`, `port` and `auth-user-pass` and stores the
   profile; the file path stays where you picked it from.
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
               (persistent profiles), and GeoLookup (background HTTP
               worker behind the connect notifications)
src/cli/       sotoportego_cli — the test client
src/gui/       Sotoportego — the native GUI client (HeaderView,
               MainWindow, CredentialsWindow, About, brand HVIF)
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

* WireGuard backend behind the same `VPNBackend` interface.
* Deskbar replicant with the same brand tile + status dot.
* IPv6 routing fix-up.
* Reconnect / backoff handling with a visible countdown.
* IPSec.


## Be careful

> **Developer's Note**: This software may contain traces of peanuts and
> LLM. It has been developed with passion for the Haiku platform.


## Support

If you find this project useful, you can buy me a coffee: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-atomozero-yellow?logo=buymeacoffee)](https://buymeacoffee.com/atomozero)
