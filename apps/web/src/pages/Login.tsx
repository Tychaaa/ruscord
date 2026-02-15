import { useState } from "react";
import { api } from "../api";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const nav = useNavigate();
  const [mode, setMode] = useState<"login" | "register">("login");

  const [email, setEmail] = useState("a@a.ru");
  const [username, setUsername] = useState("tycha");
  const [password, setPassword] = useState("123456");

  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setLoading(true);
    try {
      if (mode === "register") {
        await api.register(email, username, password);
      }
      await api.login(email, password);
      nav("/app", { replace: true });
    } catch (e: any) {
      setErr(e?.message ?? "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: "40px auto", fontFamily: "system-ui" }}>
      <h2>Ruscord</h2>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button onClick={() => setMode("login")} disabled={mode === "login"}>Login</button>
        <button onClick={() => setMode("register")} disabled={mode === "register"}>Register</button>
      </div>

      <form onSubmit={onSubmit} style={{ display: "grid", gap: 10 }}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
        {mode === "register" && (
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />
        )}
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" />

        <button disabled={loading} type="submit">
          {loading ? "..." : mode === "login" ? "Sign in" : "Create account"}
        </button>

        {err && <div style={{ color: "crimson" }}>{err}</div>}
      </form>
    </div>
  );
}