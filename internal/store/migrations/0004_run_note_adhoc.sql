-- Analyst note and label of a run (PATCH /runs/{id}) and the scope of an
-- ad-hoc run (trigger reprobe: chosen addresses and ports).
ALTER TABLE runs ADD COLUMN note TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN ad_hoc JSONB;
