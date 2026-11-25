import { useEffect, useState } from "react";
import { api, errorText, fmtPct, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, useLoad } from "../ui";

type Summary = {
  period: string;
  counts: { blocked: number; detected: number; false_positives: number };
  series: { t: string; blocked: number; detected: number }[];
  top_rules: { rule_id: string; n: number }[];
  gateways: {
    instance: string; policy_version: number; p50_ms: number | null; p95_ms: number | null; p99_ms: number | null;
    count: number; error_5xx_ratio: number; event_buffer: number; events_dropped: number; policy_source: string;
  }[];
  active_policy: { version: number; published_at: string; published_by: string } | null;
  regression: { detection_rate: number; fp_rate: number; attack_total: number; normal_total: number; ts: string; policy_version: number } | null;
  unpublished_changes: number;
  consumer: { lag: number | null; processed: number };
  alerts: { level: string; key: string; message: string }[];
};

export default function Dashboard(_: { ctx: Ctx }) {
  const [period, setPeriod] = useState("24h");
  const { data, error, reload } = useLoad(() => api.get<Summary>(`/metrics/summary?period=${period}`), [period]);

  useEffect(() => {
    const t = setInterval(reload, 15000);
    return () => clearInterval(t);
  }, [reload]);

  if (error) return <div className="error">{errorText(error)}</div>;
  if (!data) return <div className="muted">불러오는 중…</div>;

  const p95 = Math.max(...data.gateways.map((g) => g.p95_ms ?? 0), 0);
  const max = Math.max(1, ...data.series.map((s) => s.blocked + s.detected));

  return (
    <div className="stack">
      <div className="row between">
        <h2>대시보드</h2>
        <div className="seg">
          {["1h", "24h", "7d", "30d"].map((p) => (
            <button key={p} className={p === period ? "on" : ""} onClick={() => setPeriod(p)}>
              {p}
            </button>
          ))}
        </div>
      </div>

      {data.alerts.length > 0 && (
        <div className="stack tight">
          {data.alerts.map((a, i) => (
            <div key={i} className={`banner ${a.level === "critical" ? "crit" : "warn"}`}>
              <b>{a.level === "critical" ? "치명" : "경고"}</b> {a.message}
            </div>
          ))}
        </div>
      )}

      <div className="tiles">
        <Tile label="차단" value={data.counts.blocked.toLocaleString()} sub={`최근 ${period}`} tone="red" />
        <Tile label="탐지(통과)" value={data.counts.detected.toLocaleString()} sub="DETECT 모드" tone="amber" />
        <Tile label="추가 지연 p95" value={data.gateways.length ? `${p95.toFixed(2)} ms` : "—"} sub="목표 ≤ 5 ms" tone={p95 > 5 ? "red" : "green"} />
        <Tile label="정책 버전" value={data.active_policy ? `v${data.active_policy.version}` : "—"} sub={data.unpublished_changes ? `미발행 ${data.unpublished_changes}건` : "변경 없음"} />
        <Tile label="회귀 탐지율" value={fmtPct(data.regression?.detection_rate)} sub={`공격 ${data.regression?.attack_total ?? 0}건 · 목표 ≥ 95%`} tone="green" />
        <Tile label="회귀 오탐률" value={fmtPct(data.regression?.fp_rate)} sub={`정상 ${data.regression?.normal_total ?? 0}건 · 목표 ≤ 1%`} tone="green" />
      </div>

      <div className="grid2">
        <section className="card">
          <h3>시간대별 판정</h3>
          {data.series.length === 0 ? (
            <Empty>이 기간에 기록된 이벤트가 없습니다.</Empty>
          ) : (
            <div className="bars" role="img" aria-label="시간대별 차단·탐지 건수">
              {data.series.map((s) => (
                <div key={s.t} className="bar" title={`${fmtTime(s.t)} 차단 ${s.blocked} · 탐지 ${s.detected}`}>
                  <div className="seg-d" style={{ height: `${(s.detected / max) * 100}%` }} />
                  <div className="seg-b" style={{ height: `${(s.blocked / max) * 100}%` }} />
                </div>
              ))}
            </div>
          )}
          <div className="legend">
            <span className="dot red" /> 차단 <span className="dot amber" /> 탐지
          </div>
        </section>
        <section className="card">
          <h3>많이 걸린 룰</h3>
          {data.top_rules.length === 0 ? (
            <Empty>매칭 없음</Empty>
          ) : (
            <table className="table">
              <tbody>
                {data.top_rules.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="mono">{r.rule_id}</td>
                    <td className="num">{r.n.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      <section className="card">
        <h3>게이트웨이 인스턴스</h3>
        {data.gateways.length === 0 ? (
          <Empty>최근 60초 안에 상태를 보고한 게이트웨이가 없습니다.</Empty>
        ) : (
          <div className="scroll-x">
          <table className="table">
            <thead>
              <tr>
                <th>인스턴스</th><th>정책</th><th className="num">요청(5분)</th><th className="num">p50</th>
                <th className="num">p95</th><th className="num">p99</th><th className="num">5xx</th><th className="num">이벤트 버퍼</th>
              </tr>
            </thead>
            <tbody>
              {data.gateways.map((g) => (
                <tr key={g.instance}>
                  <td className="mono">{g.instance}</td>
                  <td>v{g.policy_version} <span className="muted">({g.policy_source})</span></td>
                  <td className="num">{g.count.toLocaleString()}</td>
                  <td className="num">{g.p50_ms ?? "—"}</td>
                  <td className="num">{g.p95_ms ?? "—"}</td>
                  <td className="num">{g.p99_ms ?? "—"}</td>
                  <td className="num">{fmtPct(g.error_5xx_ratio)}</td>
                  <td className="num">{g.event_buffer}{g.events_dropped ? ` (유실 ${g.events_dropped})` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
        <p className="muted small">
          이벤트 소비 대기 {data.consumer.lag ?? "?"}건 · 이 프로세스가 적재한 이벤트 {data.consumer.processed.toLocaleString()}건
          {data.active_policy && ` · v${data.active_policy.version} 발행 ${fmtTime(data.active_policy.published_at)} (${data.active_policy.published_by})`}
        </p>
      </section>
    </div>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className={`tile ${tone ?? ""}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}
