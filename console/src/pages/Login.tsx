import { FormEvent, useState } from "react";
import { api, errorText, Me } from "../api";

export default function Login({ onLogin }: { onLogin: (m: Me) => void }) {
  const [id, setId] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      onLogin(await api.post<Me>("/auth/login", { login_id: id, password: pw }));
    } catch (ex) {
      setErr(errorText(ex));
    } finally {
      setBusy(false);
      setPw("");
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h1>
          <span className="logo" aria-hidden>◆</span> MPG 관리자 콘솔
        </h1>
        <p className="muted">악성 패턴 차단 API 게이트웨이</p>
        <label>
          아이디
          <input value={id} onChange={(e) => setId(e.target.value)} autoComplete="username" required autoFocus />
        </label>
        <label>
          비밀번호
          <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
        </label>
        {err && <div className="error">{err}</div>}
        <button className="btn primary" disabled={busy}>
          {busy ? "확인 중…" : "로그인"}
        </button>
      </form>
    </div>
  );
}
