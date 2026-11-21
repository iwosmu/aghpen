# Czujka web console: design system

Source of truth for tokens: `src/index.css`. This file records the decisions behind them.

## Direction

The watch book of a night sentry. An operations console for security analysts: dense, calm, exact.
Mode: Operate. Scan speed, consistency and known patterns outrank expression.

- Dark theme first (blue-black ground, bone-paper text). The light theme is a real second theme, not an inversion: paper ground, dark navigation rail.
- Structure comes from 1 px hairline rules, not from shadows or cards. Corner radius is at most 2 px.
- One accent hue (ink blue). No gradients, no decoration, no emoji.
- The dashboard opens with one sentence that answers "what changed since the last scan" (3 seconds), then counts and the live run (30 seconds), then lists that link to detail (300 seconds).

## Colour

| Role | Token | Dark | Light |
| --- | --- | --- | --- |
| Ground | --bg | #0e131b | #f4f1e9 |
| Panel | --panel | #131a24 | #fbf9f4 |
| Raised | --raised | #1a2330 | #ffffff |
| Rule | --rule | #232e3f | #dfdacc |
| Text | --ink | #e9e5da | #161b24 |
| Secondary text | --ink-2 | #b9b7ad | #454b57 |
| Muted text | --ink-3 | #8d93a0 | #666b76 |
| Accent | --accent | #6ea3f2 | #1f55b5 |
| Danger | --danger | #e5556a | #b8303a |

State colours carry meaning and never stand alone. Each state also has its own glyph and a text label.

| State | Token | Dark | Light | Glyph |
| --- | --- | --- | --- | --- |
| New | --st-new | #22a89a | #0a8f7f | plus |
| Gone | --st-gone | #e5556a | #cf3f3f | minus |
| Changed | --st-changed | #c98500 | #b58a00 | triangle |
| Unstable | --st-unstable | #9085e9 | #6250d6 | wave |
| Expected | --st-expected | #7b8494 | #7a7f89 | dashed ring |

Magnitude uses one blue ramp, --seq-0 to --seq-5. In the dark theme more is lighter; in the light theme more is darker.
Charts use this ramp only. Text never wears a series colour.

## Type

IBM Plex Sans for interface text, IBM Plex Mono for addresses, ports, hashes, versions and every number that is compared in a column (class `num` / `mono`).
Sizes: 11, 12, 13, 15, 20, 27 px. Body is 13 px. The 27 px size is used once per screen at most (the handover sentence).

## Layout

- Fixed navigation rail (216 px) and a 44 px top bar that always shows the active run, the safety limits and the emergency stop.
- Page gutter: 16 px on mobile, 24 px from the `sm` breakpoint. Table cells align with the gutter.
- Tables use a 30 px row rhythm. Below the `md` breakpoint a table becomes a list of rows with the same data priority.
- Panels (`Panel`) have a 36 px title row and 12 px padding.

## Components

`src/ui/kit.tsx` (Button, Panel, KV, Tabs, Dialog, PageHeader, states), `src/ui/table.tsx` (DataTable, FilterBar), `src/ui/marks.tsx` (state marks, severity, interest score, class chips), `src/ui/edit.tsx` (inline edit, override note, export buttons).

## Data graphics

Hand-made SVG in `src/viz/`. No chart library.

- AddressMap: one cell is one /24 block, placed on a Hilbert curve so that neighbouring networks stay neighbours. Sparse /16 tiles split into smaller tiles. Cell state uses shape as well as colour: hollow = pending, outlined and pulsing = running, filled = done (ramp = hosts found), hatched = deferred, cross = failed.
- WeekHeatmap: 7 x 24 response rate of a host, with "no samples" drawn differently from "0 %".
- WindowPicker: the same 7 x 24 grid as an input. Paint with the pointer or with the keyboard.
- TrendRows: small multiples with a shared crosshair. No dual axis.
- RateGauge: current rate, the scan cap as a tick, the safety-policy cap as the end of the track.

## Rules that must hold

- Every score shows its reasons next to it (interest breakdown, technology evidence, stability model output).
- A control that the role cannot use is not rendered. A read-only view says that it is read-only.
- Every interactive element is reachable from the keyboard and has a visible focus ring.
- Motion is limited to progress and state change, and it respects `prefers-reduced-motion`.
