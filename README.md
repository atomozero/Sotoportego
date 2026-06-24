# Sotoportego

Native VPN client for Haiku: manage VPN connections through a privilege-separated background daemon, with a pluggable backend interface (OpenVPN first, WireGuard and IPSec to follow) and route/DNS handled as a shared daemon service.

> **Milestone 1 — compiling skeleton.** This release wires up the IPC and backend seams end to end with a *stub* backend. There is no real VPN logic yet (no OpenVPN, routing, or DNS); the stub just walks the connection state machine on a timer so the whole loop is testable.

If Sotoportego saves you time, consider supporting development: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-atomozero-yellow?logo=buymeacoffee)](https://buymeacoffee.com/atomozero)


## Features

* Privilege-separated design: a background daemon owns the VPN lifecycle, while the GUI, Deskbar replicant, and CLI are user-facing clients
* Native Haiku IPC over `BMessage` (`BApplication` / `BLooper` / `BHandler`)
* Pluggable backend interface (`VPNBackend`) — OpenVPN first, WireGuard and IPSec later
* Asynchronous state and throughput updates broadcast to subscribed clients
* Route and DNS handling designed as a shared daemon service, not duplicated per backend
* Command-line test client that proves the full connect → connected → disconnect round-trip
* Standard Haiku makefile-engine build, one binary per component
* No external dependencies beyond Haiku system libraries (`libbe`)

## Quick start

### Daemon

The daemon (`sotoportego_server`) is launched automatically by clients via `be_roster`, but you can also start it by hand to watch its log:

```
./src/server/sotoportego_server
```

### CLI

```
make
./src/cli/sotoportego_cli
```

`sotoportego_cli` launches the daemon if needed, subscribes for updates, asks it to connect with a demo profile, prints every state and stats update, then disconnects and exits. Expected output (the stub walks the machine on timers):

```
[cli] connecting to 'Demo Profile' via daemon...
[cli] state: Connecting
[cli] state: Authenticating
[cli] state: Connected
[cli] stats: in=12288 bytes  out=3072 bytes
[cli] state: Disconnected
[cli] round-trip complete; exiting
```

This round-trip is the proof that the IPC and backend seams work end to end.

## Build

Requires Haiku with GCC and the development tools (the `makefile-engine` at
`/system/develop/etc/makefile-engine`) and `libbe`. Network libraries are added
in a later milestone, when real routing and DNS land. The project builds and
runs on Haiku only.

```
make                       # builds everything: daemon + CLI
make -C src/server         # builds just the daemon
make -C src/cli            # builds just the CLI client
make clean                 # removes all build artifacts
```

## Layout

```
src/common/    Shared types and wire protocol (VPNState, VPNStats, VPNProfile, VPNProtocol.h)
src/backend/   Backend seam: VPNBackend interface + stub OpenVPNBackend
src/server/    The daemon (a BApplication / BLooper)
src/cli/       sotoportego_cli — the test client
```

| Binary               | Signature                                   |
| -------------------- | ------------------------------------------- |
| `sotoportego_server` | `application/x-vnd.VePro-SotoportegoServer` |
| `sotoportego_cli`    | `application/x-vnd.VePro-SotoportegoCLI`    |

## What's stubbed

Milestone 1 is plumbing only; the following are stubbed and marked with `TODO` in the source: the OpenVPN connection itself (the backend fakes the state machine on a timer), the OpenVPN management interface, routing, DNS, privilege escalation, `.ovpn` parsing, and credential storage.

## Roadmap

Milestone 2 — a real OpenVPN connection driven through the management interface:

* Spawn the `openvpn` binary with `--management ... --management-hold` and supervise it
* Parse the management interface (`>STATE:`, `>BYTECOUNT:`, `>PASSWORD:`) and replace the scripted timer
* `.ovpn` parsing into `VPNProfile`, with credentials stored via the Haiku keystore (`BKeyStore`)
* Routing and DNS as a shared daemon service applied on connect and restored on disconnect
* Reconnect/backoff handling and precise error reporting to clients

## Be careful
> **Developer's Note**: This software may contain traces of peanuts and LLM. It has been developed with passion for the Haiku platform.

## Support

If you find this project useful, you can buy me a coffee: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-atomozero-yellow?logo=buymeacoffee)](https://buymeacoffee.com/atomozero)
