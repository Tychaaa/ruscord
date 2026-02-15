const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8080";

let accessToken: string | null = localStorage.getItem("access_token");

type Listener = () => void;
const listeners = new Set<Listener>();

export function subscribeAuth(l: Listener) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function setAccessToken(t: string | null) {
  accessToken = t;
  if (t) localStorage.setItem("access_token", t);
  else localStorage.removeItem("access_token");

  // уведомляем React
  for (const l of listeners) l();
}
export function getAccessToken() {
  return accessToken;
}

async function refreshToken(): Promise<string | null> {
  const res = await fetch(`${API_URL}/auth/refresh`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) return null;
  const data = (await res.json()) as { access_token: string };
  setAccessToken(data.access_token);
  return data.access_token;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<T> {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", headers.get("Content-Type") ?? "application/json");

  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (res.status === 401 && retry) {
    const newTok = await refreshToken();
    if (newTok) return apiFetch<T>(path, init, false);
  }

  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j?.error) msg = j.error;
    } catch {}
    throw new Error(msg);
  }

  // некоторые ручки могут вернуть пустое тело — на будущее
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

export const api = {
  register: (email: string, username: string, password: string) =>
    apiFetch<{ id: number }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, username, password }),
    }),

  login: async (email: string, password: string) => {
    const data = await apiFetch<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setAccessToken(data.access_token);
    return data.access_token;
  },

  me: () => apiFetch<import("./types").Me>("/me"),

  userSearch: (q: string) =>
    apiFetch<import("./types").UserPublic[]>(`/users/search?q=${encodeURIComponent(q)}`),

  dmList: () => apiFetch<import("./types").DMItem[]>("/dm"),
  dmCreate: (user_id: number) =>
    apiFetch<import("./types").DMItem>("/dm", { method: "POST", body: JSON.stringify({ user_id }) }),

  roomList: () => apiFetch<import("./types").RoomItem[]>("/rooms"),
  roomCreate: (name: string) =>
    apiFetch<import("./types").RoomItem>("/rooms", { method: "POST", body: JSON.stringify({ name }) }),
  roomJoin: (code: string) =>
    apiFetch<import("./types").RoomItem>("/rooms/join", { method: "POST", body: JSON.stringify({ code }) }),

  dmMessages: (dmId: number, limit = 50) =>
    apiFetch<import("./types").MessageItem[]>(`/dm/${dmId}/messages?limit=${limit}`),
  dmSend: (dmId: number, content: string) =>
    apiFetch<import("./types").MessageItem>(`/dm/${dmId}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  roomMessages: (roomId: number, limit = 50) =>
    apiFetch<import("./types").MessageItem[]>(`/rooms/${roomId}/messages?limit=${limit}`),
  roomSend: (roomId: number, content: string) =>
    apiFetch<import("./types").MessageItem>(`/rooms/${roomId}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  wsUrl: () => (API_URL.startsWith("https") ? API_URL.replace("https", "wss") : API_URL.replace("http", "ws")) + "/ws",
};