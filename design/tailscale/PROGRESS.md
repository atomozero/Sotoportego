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
