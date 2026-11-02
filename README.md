# Alert Triage Agent

A small, eval-driven AI agent that triages security alerts — built as a
portfolio piece about *how you know an AI system works*, not just that it runs.

> **Data note:** everything here is synthetic. Indicators use documentation
> ranges (203.0.113.x, 198.51.100.x, 192.0.2.x) and `example-corp.local`
> names. No real company, host, or threat data.

## The problem

SOC analysts drown in alerts. Most queue time is spent on the same first
pass: pull context, check the indicator, guess a severity, decide whether a
human needs to look at all. That first pass is slow, inconsistent between
analysts, and a large share of it ends in "benign" anyway. The cost isn't
just analyst hours — it's the true positives that wait behind the noise.

## What the agent does

Given one structured alert, the agent returns a strict-JSON verdict:

- **verdict** — `true_positive`, `false_positive`, or `uncertain`
- **severity** — `P1`–`P4`, or `none`
- **attack_tactic** — a MITRE ATT&CK tactic name (or `None`)
- **likely_cause**, **recommended_next_step**, **rationale**
- **confidence** — and a **`human_review`** flag

If confidence falls below **0.70**, or the verdict is `uncertain`, the alert
is routed to a human instead of being auto-decided. The guardrail is the
product, not an afterthought: a triage system that fails by guessing
confidently is worse than one that asks.

## Architecture

```
alert (JSON)
   |
   v
[1] Local enrichment tools          (no external APIs)
      - indicator reputation lookup  (local fixture table)
      - MITRE ATT&CK mapping lookup  (local keyword reference)
   |
   v
[2] Prompt builder                  (alert + enrichment + output schema)
   |
   v
[3] Model client                    (model-agnostic)
      - mock  : deterministic rules — runs fully offline
      - groq  : live LLM via Groq (needs GROQ_API_KEY)
   |
   v
[4] Schema validation               (enums, required fields, confidence range)
   |
   v
[5] Confidence guardrail            (< 0.70 or 'uncertain' -> human_review)
   |
   v
verdict (JSON)
```

## Run it

No dependencies are needed for mock mode — just Python 3.10+.

```bash
# Single demo alert (mock model)
python src/triage_agent.py

# Full eval over the seed set (mock model, no API key)
python src/eval_runner.py

# Live model (optional)
pip install -r requirements.txt
export GROQ_API_KEY=...
export TRIAGE_MODEL=llama-3.3-70b-versatile   # optional
python src/eval_runner.py --mode groq
```

## How the eval works

`data/alerts_eval_seed.jsonl` holds 12 hand-labelled synthetic alerts:
7 true positives across severities, 2 benign-but-scary false positives
(admin PowerShell during approved maintenance; an authorized vulnerability
scanner), and 3 deliberately ambiguous cases where the *right* behaviour is
to ask a human.

`src/eval_runner.py` reports:

- **Verdict accuracy** — decisive cases only (true/false positive)
- **Severity accuracy** — true positives only
- **ATT&CK tactic accuracy** — true positives only
- **Ambiguous → human review** — whether ambiguous cases were routed, not guessed

### Current v0 result (mock mode)

```
Verdict accuracy (decisive cases, n=9):   100.0% (9/9)
Severity accuracy (true positives, n=7):  100.0% (7/7)
ATT&CK tactic accuracy (TP, n=7):         100.0% (7/7)
Ambiguous -> human review (n=3):          100.0% (3/3)
```

Read that correctly: the mock is a **rule-based baseline written alongside
the seed set**, so a perfect score is a sanity check that the pipeline,
schema, and guardrail work — *not* a model performance claim. The honest
test is a live model against the expanded 50-alert set, including cases
nobody wrote rules for. See `DESIGN.md` for why the eval is structured
this way, and what I'd expect to break first.

## Status

**v0** — pipeline, enrichment tools, schema, guardrail, and eval harness
complete in mock mode; Groq client wired but not yet benchmarked.
Next: grow the eval set to 50, run the live model, and publish the
comparison — including the misses.

## Layout

```
data/alerts_eval_seed.jsonl   12 labelled synthetic alerts
src/triage_agent.py           agent: tools, prompt, clients, validation, guardrail
src/eval_runner.py            eval harness and metrics
DESIGN.md                     design choices, tradeoffs, failure modes
```
