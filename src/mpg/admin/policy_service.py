"""정책 작업본(rules, rule_exceptions) → 회귀 테스트 → 버전 발행 → policy.updated 알림."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mpg.common.policy_io import exception_to_dict, policy_from_snapshot, rule_to_dict
from mpg.detection.models import Field, InspectionRequest, Location, Policy
from mpg.detection.pipeline import DetectionPipeline
from mpg.detection.regress import RegressionTester, Sample, TestReport, load_samples
from mpg.detection.rules import RuleError, load_rules

from .db import audit

CHANNEL = "policy.updated"
LOCK_KEY = 777001


class PolicyError(Exception):
    def __init__(self, status: int, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.detail = detail


@dataclass
class Datasets:
    attacks: list[Sample]
    normals: list[Sample]

    @classmethod
    def load(cls, directory: Path) -> "Datasets":
        return cls(load_samples(directory / "attack.jsonl"), load_samples(directory / "normal.jsonl"))


def _rule_row_to_dict(r) -> dict[str, Any]:
    d = {"id": r["id"], "category": r["category"], "kind": r["kind"], "weight": r["weight"],
         "mode": r["mode"], "description": r["description"], "enabled": r["enabled"]}
    if r["pattern"] is not None:
        d["pattern"] = r["pattern"]
    if r["keywords"]:
        d["keywords"] = list(r["keywords"])
    if r["signal"]:
        d["signal"] = r["signal"]
    if r["analyzer"]:
        d["analyzer"] = r["analyzer"]
    return d


async def draft_snapshot(conn, threshold: int | None = None) -> dict[str, Any]:
    rules = await conn.fetch("SELECT * FROM rules ORDER BY id")
    excs = await conn.fetch(
        "SELECT id, rule_id, path, param, expires_at FROM rule_exceptions"
        " WHERE active AND expires_at > now() ORDER BY id")
    if threshold is None:
        active = await active_version(conn)
        threshold = active["snapshot"].get("threshold", 6) if active else 6
    pts = await conn.fetch("SELECT id, path, param, prefix, threshold FROM path_thresholds WHERE active ORDER BY id")
    return {
        "threshold": threshold,
        "path_thresholds": [{"id": str(t["id"]), "path": t["path"], "param": t["param"],
                             "prefix": t["prefix"], "threshold": t["threshold"]} for t in pts],
        "rules": [_rule_row_to_dict(r) for r in rules],
        "exceptions": [{"id": str(e["id"]), "rule_id": e["rule_id"], "path": e["path"],
                        "param": e["param"], "expires_at": e["expires_at"].isoformat()} for e in excs],
    }


async def active_version(conn):
    row = await conn.fetchrow("SELECT version, snapshot, published_at, published_by FROM policy_versions"
                              " WHERE active")
    return dict(row) if row else None


def diff_snapshots(draft: dict, active: dict | None) -> list[dict[str, str]]:
    if active is None:
        return [{"type": "policy", "id": "-", "change": "initial"}]
    out = []
    a_rules = {r["id"]: r for r in active["rules"]}
    d_rules = {r["id"]: r for r in draft["rules"]}
    for rid in sorted(set(a_rules) | set(d_rules)):
        a, d = a_rules.get(rid), d_rules.get(rid)
        if (a is None and not d.get("enabled", True)) or (d is None and not a.get("enabled", True)):
            continue
        if a is None:
            out.append({"type": "rule", "id": rid, "change": "added"})
        elif d is None:
            out.append({"type": "rule", "id": rid, "change": "removed"})
        elif a != d:
            fields = sorted(k for k in set(a) | set(d) if a.get(k) != d.get(k))
            out.append({"type": "rule", "id": rid, "change": "modified:" + ",".join(fields)})
    a_exc = {str(e["id"]) for e in active.get("exceptions", [])}
    d_exc = {str(e["id"]) for e in draft.get("exceptions", [])}
    for eid in sorted(d_exc - a_exc, key=int):
        out.append({"type": "exception", "id": eid, "change": "added"})
    for eid in sorted(a_exc - d_exc, key=int):
        out.append({"type": "exception", "id": eid, "change": "removed_or_expired"})
    a_pt = {str(t["id"]): t for t in active.get("path_thresholds", [])}
    d_pt = {str(t["id"]): t for t in draft.get("path_thresholds", [])}
    for tid in sorted(set(a_pt) | set(d_pt), key=int):
        if tid not in a_pt:
            out.append({"type": "path_threshold", "id": tid, "change": "added"})
        elif tid not in d_pt:
            out.append({"type": "path_threshold", "id": tid, "change": "removed"})
        elif a_pt[tid] != d_pt[tid]:
            out.append({"type": "path_threshold", "id": tid, "change": "modified"})
    if draft.get("threshold") != active.get("threshold"):
        out.append({"type": "policy", "id": "threshold", "change": "modified"})
    return out


def compile_snapshot(snap: dict, version: int = 0) -> Policy:
    try:
        return policy_from_snapshot(snap, version=version)
    except RuleError as e:
        raise PolicyError(400, "invalid_policy", str(e)) from None


async def run_regression(policy: Policy, datasets: Datasets) -> TestReport:
    tester = RegressionTester(datasets.attacks, datasets.normals)
    return await asyncio.to_thread(tester.run, policy)


async def baseline_report(conn, active: dict | None, datasets: Datasets) -> dict | None:
    if not active:
        return None
    row = await conn.fetchrow(
        "SELECT report FROM regression_runs WHERE policy_version=$1 AND kind IN ('publish','cli')"
        " ORDER BY id DESC LIMIT 1", active["version"])
    if row:
        return row["report"]
    rep = await run_regression(compile_snapshot(active["snapshot"], active["version"]), datasets)
    return rep.to_dict()


async def known_false_positives(conn, policy: Policy, limit: int = 200) -> dict:
    """오탐으로 표시된 이벤트의 샘플이 후보 정책에서 어떻게 되는지(참고 지표)."""
    rows = await conn.fetch(
        "SELECT request_id, path, field_ref, masked_sample FROM security_events"
        " WHERE false_positive AND masked_sample <> '[redacted]' ORDER BY ts DESC LIMIT $1", limit)
    pipe = DetectionPipeline(policy)
    still = []
    for r in rows:
        loc, _, name = r["field_ref"].partition(".")
        try:
            location = Location(loc)
        except ValueError:
            location = Location.BODY
        v = pipe.inspect(InspectionRequest("POST", r["path"], (Field(location, name, r["masked_sample"]),)))
        if v.action.value == "BLOCK":
            still.append(str(r["request_id"]))
    return {"total": len(rows), "still_blocked": len(still), "still_blocked_ids": still[:20]}


def _new_items(candidate: list[dict], baseline: list[dict]) -> list[dict]:
    seen = {(x["path"], x["param"], x["payload"]) for x in baseline}
    return [x for x in candidate if (x["path"], x["param"], x["payload"]) not in seen]


async def test_draft(conn, datasets: Datasets) -> dict:
    snap = await draft_snapshot(conn)
    active = await active_version(conn)
    policy = compile_snapshot(snap)
    rep = (await run_regression(policy, datasets)).to_dict()
    base = await baseline_report(conn, active, datasets)
    reasons = TestReport.gate(rep, base)
    return {
        "changes": diff_snapshots(snap, active["snapshot"] if active else None),
        "current": _brief(base) if base else None,
        "candidate": _brief(rep),
        "passed": not reasons,
        "reasons": reasons,
        "warnings": gate_warnings(rep, base),
        "new_misses": _new_items(rep["misses"], base["misses"]) if base else rep["misses"],
        "new_false_positives": _new_items(rep["false_positive_list"], base["false_positive_list"])
        if base else rep["false_positive_list"],
        "known_false_positives": await known_false_positives(conn, policy),
        "report": rep,
    }


def gate_warnings(candidate: dict, baseline: dict | None) -> list[str]:
    """발행을 막지는 않지만 운영자가 알아야 할 변화(경로 임계값을 올리면 차단율이 내려간다)."""
    if not baseline:
        return []
    out = []
    drop = baseline.get("block_rate", 0) - candidate.get("block_rate", 0)
    if drop > 0:
        out.append(f"block_rate_dropped:{drop:.4f}")
    return out


def _brief(rep: dict) -> dict:
    keys = ("detection_rate", "block_rate", "fp_rate", "block_fp_rate", "attack_total",
            "normal_total", "blocked_fp", "false_positives")
    return {k: rep.get(k) for k in keys}


async def publish(pool, redis, datasets: Datasets, actor: str, comment: str = "",
                  client_ip: str | None = None, force_initial: bool = False) -> dict:
    try:
        return await _publish(pool, redis, datasets, actor, comment, client_ip, force_initial)
    except _Rejected as rej:
        # 거부 기록은 발행 트랜잭션이 롤백된 뒤 별도 트랜잭션으로 남긴다(같이 롤백되면 감사 기록이 사라진다).
        async with pool.acquire() as conn:
            async with conn.transaction():
                await _record_run(conn, actor, "rejected", None, rej.report)
                await audit(conn, actor, "policy.publish_rejected", "", None,
                            {"changes": rej.changes, "reasons": rej.detail["reasons"]}, comment, client_ip)
        raise PolicyError(422, "regression_failed", rej.detail) from None


class _Rejected(Exception):
    def __init__(self, detail: dict, report: dict, changes: list) -> None:
        self.detail, self.report, self.changes = detail, report, changes


async def _publish(pool, redis, datasets: Datasets, actor: str, comment: str,
                   client_ip: str | None, force_initial: bool) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", LOCK_KEY)
            snap = await draft_snapshot(conn)
            active = await active_version(conn)
            changes = diff_snapshots(snap, active["snapshot"] if active else None)
            if not changes:
                raise PolicyError(409, "no_changes")
            policy = compile_snapshot(snap)
            rep = (await run_regression(policy, datasets)).to_dict()
            base = await baseline_report(conn, active, datasets)
            reasons = TestReport.gate(rep, base)
            if reasons and not force_initial:
                detail = {
                    "reasons": reasons,
                    "current": _brief(base),
                    "candidate": _brief(rep),
                    "new_misses": _new_items(rep["misses"], base["misses"])[:50],
                    "new_false_positives": _new_items(rep["false_positive_list"],
                                                      base["false_positive_list"])[:50],
                }
                raise _Rejected(detail, rep, changes)
            version = (await conn.fetchval("SELECT coalesce(max(version), 0) FROM policy_versions")) + 1
            snap["version"] = version
            await conn.execute("UPDATE policy_versions SET active=false WHERE active")
            await conn.execute(
                "INSERT INTO policy_versions(version, snapshot, active, published_by, comment)"
                " VALUES ($1,$2,true,$3,$4)", version, snap, actor, comment)
            await _record_run(conn, actor, "publish", version, rep)
            await audit(conn, actor, "policy.publish", f"v{version}",
                        {"version": active["version"]} if active else None,
                        {"version": version, "changes": changes,
                         "detection_rate": rep["detection_rate"], "fp_rate": rep["fp_rate"]},
                        comment, client_ip)
    published_at = datetime.now(timezone.utc).isoformat()
    await notify(redis, version, published_at)
    return {"version": version, "published_at": published_at, "changes": changes,
            "report": _brief(rep), "warnings": gate_warnings(rep, base)}


async def rollback(pool, redis, datasets: Datasets, target: int, actor: str, reason: str = "",
                   client_ip: str | None = None) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", LOCK_KEY)
            row = await conn.fetchrow("SELECT snapshot FROM policy_versions WHERE version=$1", target)
            if not row:
                raise PolicyError(404, "version_not_found")
            active = await active_version(conn)
            snap = dict(row["snapshot"])
            policy = compile_snapshot(snap)
            version = (await conn.fetchval("SELECT coalesce(max(version), 0) FROM policy_versions")) + 1
            snap["version"] = version
            await _restore_working_copy(conn, snap, actor)
            await conn.execute("UPDATE policy_versions SET active=false WHERE active")
            await conn.execute(
                "INSERT INTO policy_versions(version, snapshot, active, published_by, comment, rolled_back_from)"
                " VALUES ($1,$2,true,$3,$4,$5)", version, snap, actor, f"rollback to v{target}", target)
            rep = (await run_regression(policy, datasets)).to_dict()
            await _record_run(conn, actor, "publish", version, rep)
            await audit(conn, actor, "policy.rollback", f"v{version}",
                        {"version": active["version"] if active else None},
                        {"version": version, "restored_from": target}, reason, client_ip)
    published_at = datetime.now(timezone.utc).isoformat()
    await notify(redis, version, published_at)
    return {"version": version, "restored_from": target, "published_at": published_at}


async def _restore_working_copy(conn, snap: dict, actor: str) -> None:
    ids = [r["id"] for r in snap["rules"]]
    for r in snap["rules"]:
        await upsert_rule(conn, r, actor)
    await conn.execute("UPDATE rules SET enabled=false, updated_by=$2, updated_at=now()"
                       " WHERE NOT (id = ANY($1::text[]))", ids, actor)
    keep = [int(e["id"]) for e in snap.get("exceptions", []) if e.get("id") is not None]
    await conn.execute("UPDATE rule_exceptions SET active = (id = ANY($1::int[]))", keep)
    keep_pt = [int(t["id"]) for t in snap.get("path_thresholds", []) if t.get("id") is not None]
    await conn.execute("UPDATE path_thresholds SET active = false WHERE active AND NOT (id = ANY($1::int[]))", keep_pt)
    await conn.execute("UPDATE path_thresholds SET active = true WHERE id = ANY($1::int[])", keep_pt)


async def upsert_rule(conn, d: dict, actor: str) -> None:
    load_rules([d])
    await conn.execute(
        """INSERT INTO rules(id, category, kind, pattern, keywords, signal, analyzer, weight, mode,
                             description, enabled, updated_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (id) DO UPDATE SET category=EXCLUDED.category, kind=EXCLUDED.kind,
             pattern=EXCLUDED.pattern, keywords=EXCLUDED.keywords, signal=EXCLUDED.signal,
             analyzer=EXCLUDED.analyzer, weight=EXCLUDED.weight, mode=EXCLUDED.mode,
             description=EXCLUDED.description, enabled=EXCLUDED.enabled,
             updated_by=EXCLUDED.updated_by, updated_at=now()""",
        d["id"], d["category"], d.get("kind", "regex"), d.get("pattern"),
        [str(k).lower() for k in d.get("keywords") or []], d.get("signal"), d.get("analyzer"),
        int(d["weight"]), d["mode"], d.get("description", ""), bool(d.get("enabled", True)), actor)


async def _record_run(conn, actor: str, kind: str, version: int | None, rep: dict) -> None:
    await conn.execute(
        "INSERT INTO regression_runs(run_by, kind, policy_version, detection_rate, fp_rate,"
        " attack_total, normal_total, report) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        actor, kind, version, rep["detection_rate"], rep["fp_rate"], rep["attack_total"],
        rep["normal_total"], rep)


async def notify(redis, version: int, published_at: str) -> None:
    try:
        await redis.publish(CHANNEL, json.dumps({"version": version, "published_at": published_at}))
    except Exception:
        pass


def sandbox(policy: Policy, value: str, location: str, path: str, param: str) -> dict:
    try:
        loc = Location(location)
    except ValueError:
        raise PolicyError(400, "invalid_location") from None
    pipe = DetectionPipeline(policy)
    v = pipe.inspect(InspectionRequest("POST", path, (Field(loc, param, value),)))
    out = verdict_detail(v)
    out["detect_threshold"] = min(policy.threshold, out["threshold"])
    return out


def verdict_detail(v) -> dict:
    f = v.fields[0] if v.fields else None
    return {
        "action": v.action.value,
        "risk_score": v.risk_score,
        "policy_version": v.policy_version,
        "threshold": v.fields[0].block_threshold if v.fields else 6,
        "detect_threshold": None,
        "threshold_note": "BLOCK 모드 룰 점수 합 ≥ 차단 임계값이면 차단, 전체 점수 ≥ 탐지 임계값이면 기록",
        "steps": [{"name": n, "value": t} for n, t in (f.normalization.steps if f else [])],
        "signals": sorted(f.normalization.signals) if f else [],
        "candidates": list(f.candidates) if f else [],
        "matches": [{"rule_id": m.rule_id, "category": m.category.value, "field_ref": m.field_ref,
                     "score": m.score, "mode": m.mode.value, "excepted": m.excepted,
                     "evidence": m.evidence} for m in v.matches],
        "elapsed_ms": round(v.elapsed_ms, 3),
    }


__all__ = ["PolicyError", "Datasets", "draft_snapshot", "active_version", "diff_snapshots", "publish",
           "rollback", "test_draft", "upsert_rule", "sandbox", "compile_snapshot", "rule_to_dict",
           "exception_to_dict", "verdict_detail", "notify"]
