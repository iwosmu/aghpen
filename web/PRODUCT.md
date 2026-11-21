# Product

<!-- impeccable:product-schema 1 -->

Every fact below is inferred from the task brief, `docs/PROBLEM_DEFINITION.md` and `docs/ARCHITECTURE.md`. No interview took place: the UI was built by a dispatched worker with no channel to the product owner.

## Platform

web

## Stack

React 18 + TypeScript + Vite + React Router + TanStack Query + Tailwind CSS (pinned by the brief). Built into `web/dist` and embedded in the Go binary.

## Users

Security analysts of CBI AGH (Centrum Bezpieczeństwa Informacji, Akademia Górniczo-Hutnicza, Kraków). The team monitors the university network, handles incidents and runs penetration tests. They open the console after each cyclic scan to see what changed and what needs a look. Four roles use it: administrator, editor, analyst, viewer. A hackathon jury of the same team judges it in a live demo on a projector.

## Product Purpose

Czujka ("sentinel") runs safe, cyclic discovery scans of a network above 10 000 addresses, identifies hosts, services and web technologies, and records what changes over time. Success: the analyst knows in three seconds whether anything needs attention, and can trace every score to its evidence.

## Positioning

Every score explains itself. Technology confidence lists its evidence, the interest score lists its points, and "inactive" shows the hour-of-week availability model behind it. A change that the time-of-day profile explains is marked expected and kept out of the headline.

## Operating Context

Scans run in time windows, usually at night, under a global safety policy (rate caps, port lists, exclusions, emergency stop). Analysts triage findings, acknowledge changes, edit inventory data that must survive later scans, write detection signatures in a YAML DSL, and export selected findings to DefectDojo. The address space is IPv4, planned in /24 blocks.

## Capabilities and Constraints

- The REST API contract is `docs/API.md`; the wire types are `internal/model/types.go`.
- Safe detection only: GET and HEAD, no logins, no payloads. The UI must show the safety state at all times.
- Permission-based RBAC. The UI renders only what the session permits and marks read-only views.
- UI language: Polish by default, English toggle.
- Free and open-source dependencies only.

## Brand Commitments

- Name: Czujka.
- Pinned by the brief: dark theme first with a working light theme; dense, calm, precise; monospace for addresses, ports and hashes; no decorative gradients, no generic card grids, no emoji; colour carries meaning (new, gone, changed, unstable, expected) and is never the only signal.
- Signature visual pinned by the brief: the address-space map, every /24 block as a cell on a Hilbert curve.

## Evidence on Hand

No real scan data exists at UI build time. Development fixtures model a university network (about 12 000 addresses, about 400 live hosts). Fixtures are dev-only and never ship in the production bundle.

## Product Principles

1. Three seconds, thirty seconds, one click: headline, top lists, full detail.
2. No bare labels: every score shows its reasons.
3. Safety is visible: rate caps, the effective rate and the emergency stop are always in view.
4. Analyst edits are first-class: observed and analyst-set values appear side by side.
5. Expected is not news: explained changes fold away.

## Accessibility & Inclusion

WCAG AA contrast, full keyboard reach, visible focus, colour never the only signal.
