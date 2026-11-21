-- The values a change summary needs that before and after do not carry,
-- and the model's measures kept out of the summary (p_alive, the profile
-- setting, the simhash distance). Keys: analyze.Detail*. NULL on changes
-- stored before this migration; their summary is rendered from the other
-- fields, with the stored text as the last fallback.
ALTER TABLE changes ADD COLUMN detail JSONB;
