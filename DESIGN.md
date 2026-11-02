# Design — Alert Triage Agent

The decisions below are the ones I'd expect to defend in a product or
interview review, including where this design is knowingly weak.

## 1. Structured JSON output, not free text

**Choice:** the model must return a fixed schema (verdict, severity,
ATT&CK tactic, likely cause, next step, confidence, rationale), validated
in code; invalid output is an error, not a suggestion.

**Why:** triage output feeds queues, dashboards, and SLAs. Free-text
summaries can't be routed, measured, or audited. Structured output is also
what makes the eval possible at all — you can't score a paragraph.

**Tradeoff:** you lose nuance. Mitigation is the `rationale` field and the
human-review route: where nuance matters, a human reads the alert anyway.

## 2. Enrichment before judgement (local tools)

**Choice:** before the model sees the alert, local tool functions run —
an indicator reputation lookup (small fixture table) and a MITRE ATT&CK
mapping lookup (small keyword reference). Their results go into the prompt
as evidence.

**Why:** asking an LLM to judge an alert cold invites it to hallucinate
context ("this IP looks malicious"). Grounding the judgement in tool
output — and instructing the model not to invent evidence — is the
difference between an agent and a prompt. It also mirrors how analysts
actually work: context first, verdict second.

**Tradeoff:** keyword ATT&CK mapping is crude and a local reputation table
doesn't scale. Both are deliberate v0 simplifications — the interface
(a reputation result, a candidate tactic) is what a real feed or a proper
ATT&CK classifier would slot into later.

## 3. The confidence guardrail is the product

**Choice:** confidence < 0.70, or a verdict of `uncertain`, sets
`human_review` and the alert is never auto-closed.

**Why:** the failure mode that kills triage automation in production is
not "it was slow" — it's "it confidently closed a real incident." Routing
uncertainty to humans keeps the system useful where it's sure and safe
where it isn't, and it creates the right incentive: improving coverage
means *earning* it on the eval set, not lowering the bar quietly.

**Open question I'd take into review:** is a single global threshold
right, or should P1-adjacent patterns (ransomware, account takeover) have
a *higher* bar than noisy low-severity ones? My instinct is per-severity
thresholds in v1.

## 4. Eval methodology

- **Hand-labelled, synthetic, small-on-purpose (for now).** 12 seed alerts:
  7 true positives across severities and tactics, 2 benign-but-scary false
  positives, 3 ambiguous. Seed quality beats dataset size at this stage —
  every case exists because it tests a specific behaviour.
- **Ambiguous cases are scored on routing, not verdict.** Forcing a
  TP/FP label onto a genuinely undecidable alert would teach the system
  to guess. The correct behaviour is `human_review`, so that's the metric.
- **Metrics are split, never blended.** Verdict accuracy (decisive cases),
  severity accuracy (TPs), tactic accuracy (TPs) are reported separately —
  a single "accuracy" number would hide exactly the failures you need to
  see (e.g. right verdict, wrong severity = wrong SLA).
- **The mock baseline is openly circular.** The mock client is rule-based
  and written alongside the seed set, so its 100% v0 score is a pipeline
  sanity check, not a result. I keep it in the README anyway because the
  honest baseline is what the live model has to beat — and the interesting
  v1 output will be the live model's misses on cases with no matching rule.

## 5. Known failure modes

1. **Benign-but-scary mimicry.** The two false-positive fixtures pass
   because their context is explicit ("approved change", "authorized
   scanner"). Real benign alerts rarely announce themselves so clearly;
   expect FP performance to drop on messier data.
2. **Keyword dependence.** Both the ATT&CK lookup and the mock lean on
   wording. A true positive described in unusual language falls through
   to `uncertain` — safe, but it caps automation coverage.
3. **Severity is judgement, not fact.** Two good analysts can disagree
   P1 vs P2 on the same alert. The eval treats ground truth as exact;
   a v1 improvement is accepting an "adjacent severity" band and
   reporting both numbers.
4. **Single-alert blindness.** The agent sees one alert at a time. Real
   attacks are campaigns (the spray in ALT-001 and the MFA fatigue in
   ALT-007 share an IP — a human would connect them; this agent won't).
   Correlation across alerts is the biggest known gap.
5. **Confidence is self-reported.** An LLM's stated confidence is not
   calibrated probability. The threshold is a routing heuristic, and
   calibrating it against eval outcomes is v1 work.

## 6. Model-agnostic client

The model sits behind a small interface with two implementations: a
deterministic mock (offline, reproducible, the eval always runs) and a
Groq client (any chat model via `TRIAGE_MODEL`). Rationale: the portfolio
claim is "I can evaluate and swap models," so swapping must be a flag,
not a rewrite. The same eval set runs against both, unchanged.

## 7. Deliberately out of scope (v0)

- **No SIEM / ticketing integration** — no Splunk, Sentinel, or Jira
  connectors; alerts arrive as JSONL, verdicts leave as JSON.
- **No real threat-intel feeds** — reputation is a local fixture table, by
  design and for data safety.
- **No real data, ever** — synthetic alerts only; documentation IP ranges
  and `example-corp.local` names throughout.
- **No auto-remediation** — the agent recommends a next step; it never
  blocks an IP, disables an account, or isolates a host.
- **No multi-alert correlation** — see failure mode 4; it's the v1
  candidate, not a silent omission.

## 8. Roadmap I would argue for

1. Expand the eval set to ~50, including cases written *without*
   looking at the mock rules, then benchmark the live model.
2. Per-severity confidence thresholds.
3. Cross-alert correlation for shared indicators/entities.
4. A one-page public write-up of live-model results — misses included.
