---
version: 1
slug: "web"
primary_target: "web"
related_targets: []
---

# Czujka web console

Scope: the whole authenticated console under `web/` (login, dashboard, runs, hosts, services, changes, findings, signatures, targets, profiles, import/export, administration). Visitor mode: Operate.

Audience and job: CBI AGH analysts open the console after a night scan. They need the verdict in 3 seconds, the top items in 30, and full evidence one click away. The jury watches the same screens on a projector.

Constraints pinned by the brief: dark first with a working light theme, Polish first with an English toggle, monospace for addresses, ports and hashes, colour never the only signal, role-aware rendering, emergency stop always in view.

Decision round: no user could answer (dispatched worker, coordinator cannot see local prompts). The direction was taken from the roll and the brief without a decision page.

## Direction contract

THESIS: The console is the watch book of a night sentry ("czujka" is a sentry post). Each scan run is a watch; the dashboard opens with the handover report written as one sentence. It refuses the grid of equal KPI cards with a big number and a sparkline.

OWN-WORLD: Blue-black ink ground, bone-paper text, hairline rules at one pixel, corner radius 2px at most. One ink-blue accent for selection and primary actions. Five state marks, each a drawn glyph plus a colour: new (plus, green), gone (minus, red), changed (delta, amber), unstable (wave, violet), expected (dashed ring, graphite). IBM Plex Sans for text, IBM Plex Mono for addresses, ports, hashes and counts in columns. Every table shares one 30px ruled row rhythm.

STORY: The analyst reads the handover sentence, sees whether anything needs attention, scans the entries that are new since the last watch, and opens the evidence of any score.

FIRST VIEWPORT: Left rail with navigation and the signed-in user with role. Top bar with the safety state and the emergency stop. Dashboard: the handover sentence at 28px across the top left with the delta counts as state marks under it; the active run strip with the address-space map thumbnail at the right; below, three ruled columns: top findings, recent changes, most interesting services.

FORM: Shift logbook (książka służby), candidate 5 of 7 on the grounded list. seed:4d4b0dc1a9f6dfc7. Raises taken from declined challengers: from the event catalog, the map and the chunk table are one space (hover or focus in one marks the other, every cell has a code); from the timetable, three type sizes only in working chrome, rank by weight and rule; from the reference setting, every rule is a one-pixel hairline and nothing is rounded; from the monochrome product page, every claim sits next to its proof (each headline number links to the rows behind it).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
