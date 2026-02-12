-- +goose Up

-- DM: один тред на пару пользователей (user_a < user_b)
CREATE TABLE IF NOT EXISTS dm_threads (
  id        BIGSERIAL PRIMARY KEY,
  user_a    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_dm_users_order CHECK (user_a < user_b),
  CONSTRAINT uq_dm_pair UNIQUE(user_a, user_b)
);

CREATE INDEX IF NOT EXISTS idx_dm_threads_user_a ON dm_threads(user_a);
CREATE INDEX IF NOT EXISTS idx_dm_threads_user_b ON dm_threads(user_b);

-- Rooms
CREATE TABLE IF NOT EXISTS rooms (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  owner_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invite_code TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rooms_owner_id ON rooms(owner_id);

-- Room members
CREATE TABLE IF NOT EXISTS room_members (
  room_id   BIGINT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (room_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id);

-- +goose Down
DROP TABLE IF EXISTS room_members;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS dm_threads;