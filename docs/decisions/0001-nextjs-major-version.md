# 0001 — Next.js major version

**Decision:** ForgeLab targets **Next.js 16.x** (currently 16.3.1).

**Status:** accepted, 2026-08-14. Supersedes the "Next.js 15.x" row in the
approved architecture artifact (REF-088, Technology Stack Summary).

## Context

The architecture artifact specifies Next.js 15.x. When `create-next-app@latest`
scaffolded `apps/web`, it installed 16.3.1, so the repository and the artifact
disagreed. That needed resolving deliberately rather than by whichever tool ran
last.

State of the release channels at the time of the decision:

| Channel | Version |
|---|---|
| `latest` | 16.3.1 |
| `backport` | 15.5.23 |

16.x had 35 stable releases across three minor lines. 15.x had a dedicated
`backport` dist-tag, which is what a maintenance branch looks like.

## Decision

Stay on 16.x.

- 16.3.1 is the GA default, several minor lines deep — not a bleeding-edge
  release.
- 15.x is in maintenance. Starting a greenfield project there means scheduling
  an upgrade into a seven-day MVP for no benefit.
- Nothing in the stack requires 15. What the architecture actually depends on —
  App Router, React 19 server/client composition, SSE-friendly routing — is
  fully supported.
- Downgrading costs work now and again later.

## Consequences

- The architecture artifact's stack table is stale on this row and should be
  updated in Forge; this file is the authority until then.
- React is pinned at 19.x, which 16.x requires.
- Upgrades within 16.x are routine. A future major (17.x) needs its own
  decision, not an automatic bump.
- **16.x carries breaking API changes relative to widely-published 15.x
  material.** Next generates `apps/web/AGENTS.md` and `apps/web/CLAUDE.md`
  (both committed) directing agents and developers to the version-accurate docs
  bundled at `apps/web/node_modules/next/dist/docs/`. Anyone building the
  challenge intake UI (WO-015), the arena dashboard (WO-019), or the review
  workspace (WO-049) should read those rather than relying on recalled 15.x
  patterns — this is the main cost of the decision, and it is a documentation
  lookup, not a rewrite.
