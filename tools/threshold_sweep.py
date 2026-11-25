"""임계값을 4~10으로 바꿔 가며 탐지율·오탐률을 측정한다(기획서 9장 쟁점 #1)."""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

from mpg.detection import load_policy
from mpg.detection.regress import RegressionTester, load_samples

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    base = load_policy(ROOT / "rules" / "rules.yaml")
    main_t = RegressionTester(load_samples(ROOT / "datasets" / "attack.jsonl"),
                              load_samples(ROOT / "datasets" / "normal.jsonl"))
    hard_t = RegressionTester([], load_samples(ROOT / "datasets" / "normal_hard.jsonl"))
    rows = []
    for t in range(4, 11):
        p = replace(base, threshold=t)
        r = main_t.run(p)
        h = hard_t.run(p)
        rows.append({
            "threshold": t, "detection": r.detection_rate, "block": r.block_rate,
            "fp": r.fp_rate, "block_fp": r.block_fp_rate,
            "hard_block_fp": h.blocked_fp / h.normal_total, "hard_any_fp": h.fp_rate,
        })
    print("| 임계값 | 탐지율 | 차단율 | 오탐률(정상 1,000) | 차단 오탐(정상) | 차단 오탐(어려운 40) |")
    print("|---:|---:|---:|---:|---:|---:|")
    for x in rows:
        print(f"| {x['threshold']} | {x['detection']:.2%} | {x['block']:.2%} | {x['fp']:.2%} | "
              f"{x['block_fp']:.2%} | {x['hard_block_fp']:.1%} |")
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps(rows, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
