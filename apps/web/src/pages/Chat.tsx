import { useEffect, useMemo, useRef, useState } from "react";
import { api, getAccessToken, setAccessToken } from "../api";
import type { DMItem, Me, MessageItem, RoomItem, UserPublic, WSEvent } from "../types";
import { useNavigate } from "react-router-dom";

type Active =
  | { kind: "dm"; id: number; title: string }
  | { kind: "room"; id: number; title: string }
  | null;

export default function Chat() {
  const nav = useNavigate();

  const [me, setMe] = useState<Me | null>(null);
  const [dms, setDms] = useState<DMItem[]>([]);
  const [rooms, setRooms] = useState<RoomItem[]>([]);

  const [active, setActive] = useState<Active>(null);
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [text, setText] = useState("");

  // search/create DM
  const [q, setQ] = useState("");
  const [found, setFound] = useState<UserPublic[]>([]);

  // room create/join
  const [roomName, setRoomName] = useState("");
  const [roomCode, setRoomCode] = useState("");

  const [err, setErr] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  const title = useMemo(() => active?.title ?? "Выберите чат слева", [active]);

  async function loadAll() {
    setErr(null);
    const [me, dms, rooms] = await Promise.all([api.me(), api.dmList(), api.roomList()]);
    setMe(me);
    setDms(dms);
    setRooms(rooms);
  }

  async function openActive(a: Active) {
    if (!a) return;
    setActive(a);
    setErr(null);
    const msgs =
      a.kind === "dm" ? await api.dmMessages(a.id, 50) : await api.roomMessages(a.id, 50);
    setMessages(msgs);
  }

  async function send() {
    if (!active) return;
    const content = text.trim();
    if (!content) return;
    setText("");

    try {
      const msg =
        active.kind === "dm" ? await api.dmSend(active.id, content) : await api.roomSend(active.id, content);
      // мгновенно добавить (WS тоже придёт, но это ок — можно дедуп по id позже)
      setMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
    } catch (e: any) {
      setErr(e?.message ?? "send error");
    }
  }

  // WS connect
  useEffect(() => {
    let closed = false;

    function connect() {
      const tok = getAccessToken();
      if (!tok) return;

      const ws = new WebSocket(api.wsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: "auth", token: tok }));
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as WSEvent;

          if (msg.type === "message:new") {
            const { target, message } = msg;

            // если это сейчас открытый чат — добавим в окно
            setMessages((prev) => {
              if (!active) return prev;

              const same =
                active.kind === target.kind && active.id === target.id;

              if (!same) return prev;
              if (prev.some((m) => m.id === message.id)) return prev;
              return [...prev, message];
            });
          }
        } catch {}
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (closed) return;
        // простая автопереподключалка
        setTimeout(connect, 800);
      };
    }

    connect();
    return () => {
      closed = true;
      wsRef.current?.close();
    };
  }, [active]);

  // initial load
  useEffect(() => {
    loadAll().catch((e) => setErr(e?.message ?? "load error"));
  }, []);

  async function doSearch() {
    setErr(null);
    if (!q.trim()) return setFound([]);
    try {
      const res = await api.userSearch(q.trim());
      setFound(res);
    } catch (e: any) {
      setErr(e?.message ?? "search error");
    }
  }

  async function createDM(userId: number) {
    setErr(null);
    try {
      const dm = await api.dmCreate(userId);
      const list = await api.dmList();
      setDms(list);
      setFound([]);
      setQ("");
      await openActive({ kind: "dm", id: dm.id, title: `DM: ${dm.other_user.username}` });
    } catch (e: any) {
      setErr(e?.message ?? "dm error");
    }
  }

  async function createRoom() {
    setErr(null);
    const name = roomName.trim();
    if (!name) return;
    try {
      const r = await api.roomCreate(name);
      setRoomName("");
      const list = await api.roomList();
      setRooms(list);
      await openActive({ kind: "room", id: r.id, title: `# ${r.name}` });
    } catch (e: any) {
      setErr(e?.message ?? "room error");
    }
  }

  async function joinRoom() {
    setErr(null);
    const code = roomCode.trim();
    if (!code) return;
    try {
      const r = await api.roomJoin(code);
      setRoomCode("");
      const list = await api.roomList();
      setRooms(list);
      await openActive({ kind: "room", id: r.id, title: `# ${r.name}` });
    } catch (e: any) {
      setErr(e?.message ?? "join error");
    }
  }

  function logout() {
    setAccessToken(null);
    nav("/login");
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "320px 1fr", height: "100vh", fontFamily: "system-ui" }}>
      {/* Sidebar */}
      <div style={{ borderRight: "1px solid #ddd", padding: 12, overflow: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontWeight: 700 }}>Ruscord</div>
            <div style={{ fontSize: 12, opacity: 0.7 }}>
              {me ? `${me.username} (${me.email})` : "loading..."}
            </div>
          </div>
          <button onClick={logout}>Logout</button>
        </div>

        <hr />

        <div style={{ marginBottom: 10 }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>DM: найти пользователя</div>
          <div style={{ display: "flex", gap: 6 }}>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="bob или b@b.ru" />
            <button onClick={doSearch}>Search</button>
          </div>
          {found.length > 0 && (
            <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
              {found.map((u) => (
                <button key={u.id} onClick={() => createDM(u.id)} style={{ textAlign: "left" }}>
                  {u.username} — {u.email} (id:{u.id})
                </button>
              ))}
            </div>
          )}
        </div>

        <div style={{ marginBottom: 10 }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>Комнаты</div>
          <div style={{ display: "flex", gap: 6, marginBottom: 6 }}>
            <input value={roomName} onChange={(e) => setRoomName(e.target.value)} placeholder="название" />
            <button onClick={createRoom}>Create</button>
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input value={roomCode} onChange={(e) => setRoomCode(e.target.value)} placeholder="invite code" />
            <button onClick={joinRoom}>Join</button>
          </div>
        </div>

        <hr />

        <div style={{ fontWeight: 600, marginBottom: 6 }}>DM</div>
        <div style={{ display: "grid", gap: 6, marginBottom: 12 }}>
          {dms.map((d) => (
            <button
              key={d.id}
              onClick={() => openActive({ kind: "dm", id: d.id, title: `DM: ${d.other_user.username}` })}
              style={{ textAlign: "left" }}
            >
              DM: {d.other_user.username}
            </button>
          ))}
        </div>

        <div style={{ fontWeight: 600, marginBottom: 6 }}>Rooms</div>
        <div style={{ display: "grid", gap: 6 }}>
          {rooms.map((r) => (
            <button
              key={r.id}
              onClick={() => openActive({ kind: "room", id: r.id, title: `# ${r.name}` })}
              style={{ textAlign: "left" }}
            >
              # {r.name} <span style={{ opacity: 0.6 }}>(code {r.invite_code})</span>
            </button>
          ))}
        </div>

        {err && <div style={{ color: "crimson", marginTop: 12 }}>{err}</div>}
      </div>

      {/* Main */}
      <div style={{ display: "grid", gridTemplateRows: "56px 1fr 64px" }}>
        <div style={{ borderBottom: "1px solid #ddd", padding: "12px 16px", fontWeight: 700 }}>
          {title}
        </div>

        <div style={{ padding: 16, overflow: "auto", display: "grid", gap: 10 }}>
          {messages.map((m) => (
            <div key={m.id} style={{ padding: 10, border: "1px solid #eee", borderRadius: 8 }}>
              <div style={{ fontSize: 12, opacity: 0.7 }}>
                <b>{m.author.username}</b> • {new Date(m.created_at).toLocaleString()} • id:{m.id}
              </div>
              <div>{m.content}</div>
            </div>
          ))}
          {messages.length === 0 && <div style={{ opacity: 0.6 }}>Сообщений пока нет</div>}
        </div>

        <div style={{ borderTop: "1px solid #ddd", padding: 12, display: "flex", gap: 8 }}>
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={active ? "Сообщение..." : "Сначала выбери чат"}
            disabled={!active}
            onKeyDown={(e) => {
              if (e.key === "Enter") send();
            }}
            style={{ flex: 1 }}
          />
          <button onClick={send} disabled={!active}>Send</button>
        </div>
      </div>
    </div>
  );
}
