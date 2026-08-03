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
