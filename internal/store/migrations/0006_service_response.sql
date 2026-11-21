-- Whether the latest observation of a service answered HTTP clearly slower
-- than the service's own baseline (analyze.ResponseSeries). Set by the
-- analysis of each run; the response time itself is in the observation
-- result (http.response_ms).
ALTER TABLE services ADD COLUMN response_slow BOOLEAN NOT NULL DEFAULT false;
