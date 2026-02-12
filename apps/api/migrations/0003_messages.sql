-- +goose Up

CREATE TABLE IF NOT EXISTS messages (
  id           BIGSERIAL PRIMARY KEY,
  dm_thread_id BIGINT REFERENCES dm_threads(id) ON DELETE CASCADE,
  room_id      BIGINT REFERENCES rooms(id) ON DELETE CASCADE,
  author_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content      TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_message_target CHECK (
    (dm_thread_id IS NOT NULL AND room_id IS NULL) OR
    (dm_thread_id IS NULL AND room_id IS NOT NULL)
  )
);

-- пагинация по id
CREATE INDEX IF NOT EXISTS idx_messages_dm_id_id   ON messages(dm_thread_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_room_id_id ON messages(room_id, id DESC);

-- +goose Down
DROP TABLE IF EXISTS messages;