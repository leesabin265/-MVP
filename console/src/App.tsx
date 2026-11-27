import { useCallback, useEffect, useState } from "react";
import { api, atLeast, Me, setCsrf, setUnauthorizedHandler } from "./api";
import { Toasts, useToasts } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Rules from "./pages/Rules";
import Exceptions from "./pages/Exceptions";
import Thresholds from "./pages/Thresholds";
import Policy from "./pages/Policy";
import Sandbox from "./pages/Sandbox";
import Audit from "./pages/Audit";
import Classroom from "./pages/Classroom";

type Tab = "dashboard" | "events" | "rules" | "exceptions" | "thresholds" | "policy" | "sandbox" | "audit" | "classroom";
const TABS: { id: Tab; label: string; need?: "OPERATOR" | "ADMIN" }[] = [
  { id: "dashboard", label: "대시보드" },
  { id: "events", label: "탐지 로그" },
  { id: "rules", label: "룰" },
  { id: "exceptions", label: "예외" },
  { id: "thresholds", label: "경로별 설정" },
  { id: "policy", label: "정책 버전" },
  { id: "sandbox", label: "샌드박스", need: "OPERATOR" },
  { id: "audit", label: "감사 기록", need: "ADMIN" },
  { id: "classroom", label: "수업 참여", need: "OPERATOR" },
];

export type Ctx = {
  me: Me;
  toast: (msg: string, kind?: "ok" | "err") => void;
  changes: number;
  refreshChanges: () => void;
  openEvent: (id: string) => void;
};

function readTab(): Tab {
  const h = location.hash.replace("#", "").split("/")[0] as Tab;
  return TABS.some((t) => t.id === h) ? h : "dashboard";
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [tab, setTab] = useState<Tab>(readTab());
  const [changes, setChanges] = useState(0);
  const [focusEvent, setFocusEvent] = useState<string | null>(null);
  const { toasts, toast } = useToasts();

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null));
    api
      .get<Me>("/auth/me")
      .then((m) => {
        setCsrf(m.csrf_token);
        setMe(m);
      })
      .catch(() => setMe(null));
    const onHash = () => setTab(readTab());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const refreshChanges = useCallback(() => {
    api
      .get<{ changes: unknown[] }>("/policy/changes")
      .then((r) => setChanges(r.changes.length))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (me) refreshChanges();
  }, [me, refreshChanges]);

  if (me === undefined) return <div className="center muted">불러오는 중…</div>;
  if (me === null)
    return (
      <Login
        onLogin={(m) => {
          setCsrf(m.csrf_token);
          setMe(m);
        }}
      />
    );

  const go = (t: Tab) => {
    location.hash = t;
    setTab(t);
  };
  const ctx: Ctx = {
    me,
    toast,
    changes,
    refreshChanges,
    openEvent: (id) => {
      setFocusEvent(id);
      go("events");
    },
  };

  const logout = async () => {
    await api.post("/auth/logout").catch(() => {});
    setMe(null);
  };

  return (
    <div className="shell">
      <header className="top">
        <div className="brand">
          <span className="logo" aria-hidden>◆</span> MPG 관리자 콘솔
        </div>
        <nav className="tabs">
          {TABS.filter((t) => !t.need || atLeast(me.role, t.need)).map((t) => (
            <button key={t.id} className={tab === t.id ? "tab active" : "tab"} onClick={() => go(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <div className="who">
          <span className="badge">{me.role}</span> {me.login_id}
          <button className="link" onClick={logout}>
            로그아웃
          </button>
        </div>
      </header>
      {changes > 0 && atLeast(me.role, "OPERATOR") && (
        <div className="banner warn">
          미발행 변경 {changes}건이 있습니다. 회귀 테스트 후 발행해야 게이트웨이에 반영됩니다.
          <button className="btn small" onClick={() => go("policy")}>
            검토하고 발행
          </button>
        </div>
      )}
      <main className="main">
        {tab === "dashboard" && <Dashboard ctx={ctx} />}
        {tab === "events" && <Events ctx={ctx} focus={focusEvent} clearFocus={() => setFocusEvent(null)} />}
        {tab === "rules" && <Rules ctx={ctx} />}
        {tab === "exceptions" && <Exceptions ctx={ctx} />}
        {tab === "thresholds" && <Thresholds ctx={ctx} />}
        {tab === "policy" && <Policy ctx={ctx} />}
        {tab === "sandbox" && <Sandbox ctx={ctx} />}
        {tab === "audit" && <Audit ctx={ctx} />}
        {tab === "classroom" && <Classroom ctx={ctx} />}
      </main>
      <Toasts toasts={toasts} />
    </div>
  );
}
