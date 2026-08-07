# Tailscale support — working docs

This directory coordinates the from-scratch, in-process **Tailscale** backend
for Sotoportego (level C — full Tailscale, not just a static WireGuard peer).
It is the shared brain for the loop-mode build.

| File | What it is |
|---|---|
| `DESIGN.md` | The architecture: modules, crypto, lifecycle, threading, how it plugs into the existing `VPNBackend` seam. Read this first. |
| `ROADMAP.md` | 9 phases (0–8), each a committable milestone with a concrete "Done when" check and a dependency order. The build plan. |
| `PROGRESS.md` | Living log, newest on top. Every loop iteration appends what it did, the build status, and the next step. |

> Note: the main README keeps `docs/` out of the shipping tree (it is
> `.gitignore`d). These planning files live under `design/tailscale/` instead,
> deliberately tracked on the `Tailscale` branch to drive the incremental
> build; they can be squashed/removed before any release merge.

## Loop-mode protocol

The build runs as a self-continuing loop. Each iteration does exactly this:

1. **Read** `ROADMAP.md` (find the current `[~]`/next `[ ]`) and the top of
   `PROGRESS.md` (the "Next" line from last time).
2. **Do the next concrete step** — one coherent, reviewable chunk. Prefer
   finishing a roadmap sub-item over starting three.
3. **Build** with `make` when source changed; keep the tree green. (Note: the
   project builds on Haiku only — in a non-Haiku CI/sandbox, compilation of
   Haiku-API code can't be run; in that case do a syntax/consistency self-review
   and say so in the log rather than claiming a green build.)
4. **Update** `ROADMAP.md` checkboxes and prepend a `PROGRESS.md` entry ending
   in a single clear **Next** step.
5. **Commit** to the `Tailscale` branch with a descriptive message and push.
6. **Stop or continue**: if a phase's "Done when" is met, note it and roll to
   the next phase; if blocked on a real external dependency (e.g. needs a live
   Headscale or on-device Haiku), record the blocker in `PROGRESS.md` and raise
   it rather than spinning.

Guardrails:
- Never fake a build result. Haiku-only code can't be compiled off-Haiku — say
  so honestly in the log.
- Keep each commit self-contained and reviewable; small green steps beat big
  broken ones.
- Treat all control-server / netmap input as untrusted (bounds, key-length and
  route-safety checks) per `DESIGN.md` §8.
