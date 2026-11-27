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
  phase: "lobby" | "vote" | "reveal" | "challenge" | "end";
  q: number;
  quiz_len: number;
  url: string;
  students: number;
  question?: { id: string; title: string; shown: string; hint: string; explain: string };
  votes?: { block: number; pass: number };
  result?: { status: number; blocked: boolean; request_id: string } | null;
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
  const phase = (p: State["phase"], q?: number) => act("/class/phase", q === undefined ? { phase: p } : { phase: p, q });

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
  const quizActive = s.phase === "vote" || s.phase === "reveal";

  return (
    <div className="stack cls">
      <div className="cls-bar">
        <span className="cls-count">참여 {s.students}명</span>
        <div className="cls-controls">
          <button className={on(s.phase === "lobby")} disabled={busy} onClick={() => phase("lobby")}>대기(QR)</button>
          {Array.from({ length: s.quiz_len }, (_, i) => (
            <span key={i} className="cls-pair">
              <button className={on(quizActive && s.q === i && s.phase === "vote")} disabled={busy} onClick={() => phase("vote", i)}>
                Q{i + 1} 투표
              </button>
              <button className={on(quizActive && s.q === i && s.phase === "reveal")} disabled={busy} onClick={() => phase("reveal", i)}>
                Q{i + 1} 공개
              </button>
            </span>
          ))}
          <button className={on(s.phase === "challenge")} disabled={busy} onClick={() => phase("challenge")}>챌린지</button>
          <button className={on(s.phase === "end")} disabled={busy} onClick={() => phase("end")}>종료</button>
          <button
            className="btn small"
            disabled={busy}
            onClick={() => confirm("참여자·투표·챌린지 기록을 모두 지울까요?") && act("/class/reset")}
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
          <p className="muted small">학생 휴대폰은 이 PC와 같은 Wi-Fi에 있어야 합니다.</p>
        </div>
      )}

      {quizActive && s.question && s.votes && (
        <div className="card stack">
          <span className="badge">예측 투표 {s.q + 1} / {s.quiz_len}</span>
          <h1 className="cls-title">{s.question.title}</h1>
          <pre className="cls-payload">{s.question.shown}</pre>
          <p className="muted">{s.question.hint}</p>
          <VoteBar label="🛡️ 막힌다" n={s.votes.block} total={s.votes.block + s.votes.pass} kind="block" />
          <VoteBar label="🚪 통과한다" n={s.votes.pass} total={s.votes.block + s.votes.pass} kind="pass" />
          {s.phase === "reveal" && s.result && (
            <>
              <div className={s.result.blocked ? "cls-result block" : "cls-result pass"}>
                {s.result.blocked ? "🛡️ 막혔습니다" : "🚪 통과했습니다"} (HTTP {s.result.status})
              </div>
              <p className="cls-explain">{s.question.explain}</p>
              {s.result.request_id && (
                <button className="btn small" onClick={() => ctx.openEvent(s.result!.request_id)}>
                  탐지 로그에서 이 요청 보기
                </button>
              )}
            </>
          )}
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

function VoteBar({ label, n, total, kind }: { label: string; n: number; total: number; kind: "block" | "pass" }) {
  return (
    <div className="cls-barrow">
      <span>{label}</span>
      <div className="cls-track">
        <div className={`cls-fill ${kind}`} style={{ width: `${total ? (100 * n) / total : 0}%` }} />
      </div>
      <b>{n}</b>
    </div>
  );
}
