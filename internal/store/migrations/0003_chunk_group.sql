-- The work group of a chunk (model.Chunk.Group): the seq of the first chunk
-- that one scanner process took together with it. 0 = not started yet.
ALTER TABLE chunks ADD COLUMN work_group INT NOT NULL DEFAULT 0;
