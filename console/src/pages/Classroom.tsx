import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, errorText } from "../api";
import type { Ctx } from "../App";

// 수업 발표용 실시간 참여(발표자 화면). 학생은 휴대폰으로 classroom 서비스(8080)에 접속하고,
// 이 탭은 admin-api(/admin/api/class/*)를 거쳐 단계 진행·공개를 한다.
// 학생이 보낸 공격 문자열은 JSX 텍스트로만 렌더링한다(React가 이스케이프).

type Crack = { label: string; count: number; request_id: string };
type Recent = { nick: string; attack: string; payload: string; blocked: boolean; disguises: string[] };
type Board = { nick: string; cracked: number; attacks: string[] };
type State = {
  phase: "lobby" | "challenge" | "end";
  url: string;
  students: number;
  challenge: {
    total: number; blocked: number; passed: number;
    cracks: Record<string, Crack>;
    disguise_wins: { label: string; n: number }[];
    recent: Recent[];
    leaderboard: Board[];
  };
};

export default function Classroom({ ctx }: { ctx: Ctx }) {
  const [s, setS] = useState<State | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  const load = useCallback(async () => {
    try {
      setS(await api.get<State>("/class/state"));
      setErr(null);
    } catch (e) {
      setErr(e);
    }
  }, []);

  useEffect(() => {
    load();
    timer.current = window.setInterval(load, 1000);
    return () => window.clearInterval(timer.current);
  }, [load]);

  const act = async (path: string, body: unknown = {}) => {
    setBusy(true);
    try {
      await api.post(path, body);
      await load();
    } catch (e) {
      ctx.toast(errorText(e), "err");
    } finally {
      setBusy(false);
    }
  };
  const phase = (p: State["phase"]) => act("/class/phase", { phase: p });

  if (err && !s) {
    const down = err instanceof ApiError && err.status === 503;
    return (
      <div className="stack">
        <h2>수업 참여</h2>
        {down ? (
          <div className="card">
            <p>수업 참여 서비스가 꺼져 있습니다. 프로젝트 폴더에서 아래 명령으로 띄우세요(발표가 끝나면 <code>down</code>).</p>
            <pre className="code block">./deploy/class-up.sh</pre>
          </div>
        ) : (
          <div className="error">{errorText(err)}</div>
        )}
      </div>
    );
  }
  if (!s) return <p className="muted">불러오는 중…</p>;

  const on = (cond: boolean) => (cond ? "btn small primary" : "btn small");

  return (
    <div className="stack cls">
      <div className="cls-bar">
        <span className="cls-count">참여 {s.students}명</span>
        <div className="cls-controls">
          <button className={on(s.phase === "lobby")} disabled={busy} onClick={() => phase("lobby")}>대기(QR)</button>
          <button className={on(s.phase === "challenge")} disabled={busy} onClick={() => phase("challenge")}>챌린지 시작</button>
          <button className={on(s.phase === "end")} disabled={busy} onClick={() => phase("end")}>종료</button>
          <button
            className="btn small"
            disabled={busy}
            onClick={() => confirm("참여자·챌린지 기록을 모두 지울까요?") && act("/class/reset")}
          >
            초기화
          </button>
        </div>
      </div>

      {s.phase === "lobby" && (
        <div className="card cls-center">
          <h1>휴대폰으로 접속하세요</h1>
          <img className="cls-qr" src={`/admin/api/class/qr.svg?u=${encodeURIComponent(s.url)}`} alt="학생 접속 QR 코드" />
          <p className="cls-url">{s.url}</p>
          <p className="muted small">학생 휴대폰은 이 PC와 같은 Wi-Fi에 있어야 합니다. 챌린지를 시작하면 학생 화면이 바뀝니다.</p>
        </div>
      )}

      {(s.phase === "challenge" || s.phase === "end") && (
        <>
          <div className="cls-stats">
            <div className="card cls-stat block"><b>{s.challenge.blocked}</b><span>차단</span></div>
            <div className="card cls-stat pass"><b>{s.challenge.passed}</b><span>통과</span></div>
            <div className="card cls-stat"><b>{s.challenge.total}</b><span>전체 시도</span></div>
          </div>
          <div className="cls-cracks">
            {Object.entries(s.challenge.cracks).map(([id, c]) => (
              <div key={id} className="card cls-crack">
                <div className="cls-crack-head">
                  <b>{c.label}</b>
                  {c.request_id && (
                    <button className="link small" onClick={() => ctx.openEvent(c.request_id)}>로그</button>
                  )}
                </div>
                <div className={c.count ? "cls-crack-n done" : "cls-crack-n"}>
                  {c.count ? `${c.count}명 뚫음 🔓` : "아직 아무도 못 뚫음 🔒"}
                </div>
              </div>
            ))}
          </div>
          <div className="cls-cols">
            <div className="card stack">
              <h3>🏆 순위 (서로 다른 공격을 뚫은 수)</h3>
              {!s.challenge.leaderboard.length && <p className="muted">아직 뚫은 사람이 없습니다.</p>}
              <ol className="cls-board">
                {s.challenge.leaderboard.map((b) => (
                  <li key={b.nick}>{b.nick} — {b.cracked}개 {b.cracked >= 3 ? "👑" : ""}</li>
                ))}
              </ol>
              {!!s.challenge.disguise_wins.length && (
                <>
                  <h3>가장 잘 통한 변장</h3>
                  <ul className="cls-list small">
                    {s.challenge.disguise_wins.map((d, i) => (
                      <li key={i}>{d.label} <span className="muted">— {d.n}회 통과</span></li>
                    ))}
                  </ul>
                </>
              )}
            </div>
            {s.phase === "challenge" && (
              <div className="card stack">
                <h3>최근 시도</h3>
                <ul className="cls-list small">
                  {s.challenge.recent.map((r, i) => (
                    <li key={i}>
                      <span className={r.blocked ? "badge red" : "badge green"}>{r.blocked ? "막힘" : "통과"}</span>{" "}
                      {r.nick} <span className="muted small">{r.attack}</span>{" "}
                      <span className="muted small">{r.disguises.length ? r.disguises.join(" ") : "변장 없음"}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
