-- When a finding became "resolved". A resolved finding is reopened only by
-- an observation made after this time (store.UpsertFindings), so a rule
-- evaluation over unchanged data or a run that observed the cause before
-- the resolution does not reopen it. Findings that are resolved today count
-- as resolved now.
ALTER TABLE findings ADD COLUMN resolved_at TIMESTAMPTZ;
UPDATE findings SET resolved_at = now() WHERE status = 'resolved';

CREATE FUNCTION czujka_finding_resolved_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'resolved' THEN
    IF TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'resolved' THEN
      NEW.resolved_at := now();
    END IF;
  ELSE
    NEW.resolved_at := NULL;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER findings_resolved_at BEFORE INSERT OR UPDATE OF status ON findings
  FOR EACH ROW EXECUTE FUNCTION czujka_finding_resolved_at();
