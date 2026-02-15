export type Me = { id: number; email: string; username: string };

export type UserPublic = { id: number; username: string; email: string };

export type DMItem = { id: number; other_user: UserPublic };

export type RoomItem = { id: number; name: string; invite_code: string; owner_id: number };

export type MessageItem = {
  id: number;
  content: string;
  created_at: string;
  author: { id: number; username: string };
};

export type WSReady = { type: "ready"; dm_ids: number[]; room_ids: number[] };

export type WSMessageNew = {
  type: "message:new";
  target: { kind: "dm" | "room"; id: number };
  message: MessageItem;
};

export type WSEvent = WSReady | WSMessageNew;