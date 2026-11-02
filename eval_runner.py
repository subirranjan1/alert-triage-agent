"""Run the triage agent over the labelled eval set and score it.

Usage (from the project root):
    python src/eval_runner.py                  # mock mode, no API key
    python src/eval_runner.py --mode groq      # live model (needs GROQ_API_KEY)

Metrics:
- Verdict accuracy   — exact match on decisive cases (true/false positive).
                       'ambiguous' ground-truth cases are excluded here and
                       scored separately on human-review routing.
- Severity accuracy  — exact match on true positives.
- Tactic accuracy    — exact MITRE ATT&CK tactic match on true positives.
- Ambiguous routing  — share of ambiguous cases correctly sent to a human.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage_agent import TriageAgent, get_model_client  # noqa: E402

DEFAULT_EVAL = Path(__file__).parent.parent / "data" / "alerts_eval_seed.jsonl"


def pct(numerator: int, denominator: int) -> str:
    return f"{100 * numerator / denominator:.1f}%" if denominator else "n/a"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["mock", "groq"], default="mock")
    parser.add_argument("--eval-file", default=str(DEFAULT_EVAL))
    args = parser.parse_args()

    alerts = [json.loads(line) for line in Path(args.eval_file).read_text().splitlines() if line.strip()]
    agent = TriageAgent(get_model_client(args.mode))

    verdict_hit = verdict_n = severity_hit = tactic_hit = tp_n = 0
    amb_hit = amb_n = 0
    rows = []

    for alert in alerts:
        truth = alert["ground_truth"]
        result = agent.triage(alert)
        if truth["verdict"] in ("true_positive", "false_positive"):
            verdict_n += 1
            verdict_hit += result["verdict"] == truth["verdict"]
        if truth["verdict"] == "true_positive":
            tp_n += 1
            severity_hit += result["severity"] == truth["severity"]
            tactic_hit += result["attack_tactic"] == truth["attack_tactic"]
        if truth["verdict"] == "ambiguous":
            amb_n += 1
            amb_hit += bool(result["human_review"])
        rows.append(
            f"{alert['id']:<8} truth={truth['verdict']:<15} "
            f"pred={result['verdict']:<15} sev={result['severity']:<4} "
            f"tactic={result['attack_tactic']:<18} conf={result['confidence']:.2f} "
            f"human_review={result['human_review']}"
        )

    print(f"Eval: {len(alerts)} alerts | mode={args.mode}")
    print("-" * 78)
    for row in rows:
        print(row)
    print("-" * 78)
    print(f"Verdict accuracy (decisive cases, n={verdict_n}):  {pct(verdict_hit, verdict_n)} ({verdict_hit}/{verdict_n})")
    print(f"Severity accuracy (true positives, n={tp_n}):      {pct(severity_hit, tp_n)} ({severity_hit}/{tp_n})")
    print(f"ATT&CK tactic accuracy (true positives, n={tp_n}): {pct(tactic_hit, tp_n)} ({tactic_hit}/{tp_n})")
    print(f"Ambiguous -> human review (n={amb_n}):              {pct(amb_hit, amb_n)} ({amb_hit}/{amb_n})")


if __name__ == "__main__":
    main()
