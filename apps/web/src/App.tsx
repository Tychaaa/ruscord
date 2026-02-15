import { Route, Routes, Navigate } from "react-router-dom";
import Login from "./pages/Login";
import Chat from "./pages/Chat";
import { getAccessToken, subscribeAuth } from "./api";
import { useSyncExternalStore } from "react";

export default function App() {
  const authed = useSyncExternalStore(
    subscribeAuth,
    () => !!getAccessToken(),
    () => false
  );

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/app" element={authed ? <Chat /> : <Navigate to="/login" replace />} />
      <Route path="*" element={<Navigate to={authed ? "/app" : "/login"} replace />} />
    </Routes>
  );
}
