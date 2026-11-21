-- The status that the stability model gave a host at one observation.
-- The diff of a later run needs it ("was the host already reported inactive?").
ALTER TABLE host_observations ADD COLUMN status TEXT NOT NULL DEFAULT '';
