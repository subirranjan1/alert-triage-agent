"""Security alert-triage agent (v0).

Takes one structured alert, enriches it with local tools, asks a model
(or a deterministic mock) for a structured verdict, validates the output,
and routes low-confidence cases to a human.

Design notes live in DESIGN.md. Synthetic data only.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Protocol

CONFIDENCE_THRESHOLD = 0.70

VERDICTS = {"true_positive", "false_positive", "uncertain"}
SEVERITIES = {"P1", "P2", "P3", "P4", "none"}
TACTICS = {
    "Initial Access", "Execution", "Persistence", "Credential Access",
    "Reconnaissance", "Exfiltration", "Impact", "None",
}

# ---------------------------------------------------------------------------
# Local enrichment tools (no external APIs)
# ---------------------------------------------------------------------------

# Small fixture table for the synthetic indicators used in the eval seed.
# TEST-NET addresses (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) are
# documentation ranges, never real hosts.
INDICATOR_REPUTATION: dict[str, dict[str, str]] = {
    "203.0.113.66": {"reputation": "malicious_fixture", "note": "Seen in spray/fatigue fixtures"},
    "203.0.113.99": {"reputation": "malicious_fixture", "note": "Payload host fixture"},
    "203.0.113.120": {"reputation": "unknown", "note": "Previously unseen external IP"},
    "198.51.100.77": {"reputation": "unknown", "note": "New-country logon source"},
    "198.51.100.10": {"reputation": "authorized_scanner", "note": "Internal vulnerability scanner"},
    "192.0.2.45": {"reputation": "internal_asset", "note": "Internal server"},
    "payload.example.net": {"reputation": "malicious_fixture", "note": "Payload domain fixture"},
    "tunnel.example.net": {"reputation": "suspicious_fixture", "note": "Newly registered domain fixture"},
}


def lookup_indicator_reputation(indicator: str) -> dict[str, str]:
    """Look up one indicator in the local reputation table."""
    if indicator in INDICATOR_REPUTATION:
        return INDICATOR_REPUTATION[indicator]
    if indicator.endswith((".local", ".example-corp.local")):
        return {"reputation": "internal_asset", "note": "Internal naming convention"}
    return {"reputation": "unknown", "note": "Not in local table"}


# Keyword -> (tactic, technique) reference, a deliberately small subset.
ATTACK_REFERENCE: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"password spray|mfa push|mfa fatigue|credential", re.I), "Credential Access", "T1110 / T1621"),
    (re.compile(r"impossible travel|dormant.*interactive|valid account", re.I), "Initial Access", "T1078"),
    (re.compile(r"powershell|encoded command|script", re.I), "Execution", "T1059.001"),
    (re.compile(r"access key|administratoraccess|persistence|policy.*attach", re.I), "Persistence", "T1136 / T1098"),
    (re.compile(r"port scan|nmap|syn sweep|scan", re.I), "Reconnaissance", "T1046"),
    (re.compile(r"dns txt|tunnel|exfiltrat", re.I), "Exfiltration", "T1048"),
    (re.compile(r"ransom|\.locked|shadow copies deleted", re.I), "Impact", "T1486"),
]


def map_to_attack(alert: dict[str, Any]) -> dict[str, str]:
    """Map alert text to a candidate MITRE ATT&CK tactic/technique."""
    text = f"{alert.get('title', '')} {alert.get('log_snippet', '')}"
    for pattern, tactic, technique in ATTACK_REFERENCE:
        if pattern.search(text):
            return {"tactic": tactic, "technique": technique}
    return {"tactic": "None", "technique": ""}


def enrich(alert: dict[str, Any]) -> dict[str, Any]:
    """Run all local enrichment tools for an alert."""
    return {
        "indicators": {
            ind: lookup_indicator_reputation(ind)
            for ind in alert.get("indicators", [])
        },
        "attack_candidate": map_to_attack(alert),
    }


# ---------------------------------------------------------------------------
# Model clients (model-agnostic; mock runs fully offline)
# ---------------------------------------------------------------------------


class ModelClient(Protocol):
    def triage(self, alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
        """Return a raw verdict dict matching OUTPUT_SCHEMA."""
        ...


class MockModelClient:
    """Deterministic stand-in for an LLM, so the eval runs with no API key.

    Rule-based on purpose: it makes the offline eval reproducible and gives
    the live model a baseline to beat. It will miss things a real model
    catches — those misses are the interesting eval output.
    """

    def triage(self, alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
        text = f"{alert.get('title', '')} {alert.get('log_snippet', '')}".lower()
        tactic = enrichment["attack_candidate"]["tactic"]
        reps = {v["reputation"] for v in enrichment["indicators"].values()}

        def out(verdict: str, severity: str, attack_tactic: str,
                confidence: float, cause: str, step: str) -> dict[str, Any]:
            return {
                "verdict": verdict, "severity": severity,
                "attack_tactic": attack_tactic, "likely_cause": cause,
                "recommended_next_step": step, "confidence": confidence,
                "rationale": f"Mock rules matched on alert text and enrichment (candidate tactic: {tactic}).",
            }

        # Benign-but-scary patterns first: context beats keywords.
        if "authorized_scanner" in reps or "scheduled maintenance" in text:
            return out("false_positive", "none", "None", 0.90,
                       "Activity matches an approved scanner window or change ticket.",
                       "Close as benign; note the window in the case.")
        # Clear attacks.
        if "ransom" in text or ".locked" in text:
            return out("true_positive", "P1", "Impact", 0.93,
                       "Ransomware detonation on a file server.",
                       "Isolate the host, preserve evidence, invoke incident response.")
        if "password spray" in text:
            return out("true_positive", "P2", "Credential Access", 0.88,
                       "Password spray from a known-bad fixture IP.",
                       "Block the source IP, force resets for targeted accounts, hunt for successes.")
        if "mfa" in text and "approved" in text:
            return out("true_positive", "P2", "Credential Access", 0.86,
                       "MFA fatigue attack with one approved prompt.",
                       "Revoke sessions, reset credentials, interview the user.")
        if "impossible travel" in text:
            return out("true_positive", "P1", "Initial Access", 0.84,
                       "Account takeover: impossible travel plus a forwarding rule.",
                       "Disable the account, remove the inbox rule, review mailbox activity.")
        if "encoded" in text and "powershell" in text:
            return out("true_positive", "P1", "Execution", 0.90,
                       "Malicious script execution from an email attachment.",
                       "Isolate the workstation, capture the payload, hunt for the same hash.")
        if "administratoraccess" in text:
            return out("true_positive", "P2", "Persistence", 0.85,
                       "Privilege escalation and persistence outside a change window.",
                       "Detach the policy, delete the new key, review the account's actions.")
        if "dns txt" in text:
            return out("true_positive", "P2", "Exfiltration", 0.83,
                       "DNS tunnelling consistent with data exfiltration.",
                       "Block the domain, scope what data left, review the workstation.")
        # Everything else: honestly uncertain, low confidence -> human review.
        return out("uncertain", "P3", tactic if tactic != "None" else "None", 0.55,
                   "Alert lacks enough context to decide automatically.",
                   "Route to an analyst for context (asset owner, data classification, expected behaviour).")


class GroqModelClient:
    """Live client (optional). Requires GROQ_API_KEY and the groq package."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("TRIAGE_MODEL", "llama-3.3-70b-versatile")

    def triage(self, alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
        from groq import Groq  # imported lazily so mock mode needs no dependency

        client = Groq(api_key=os.environ["GROQ_API_KEY"])
        response = client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a security alert-triage analyst. Reply with JSON only."},
                {"role": "user", "content": build_prompt(alert, enrichment)},
            ],
        )
        return json.loads(response.choices[0].message.content)


def get_model_client(mode: str = "mock") -> ModelClient:
    if mode == "groq":
        return GroqModelClient()
    return MockModelClient()


# ---------------------------------------------------------------------------
# Prompt, schema validation, and the agent itself
# ---------------------------------------------------------------------------

OUTPUT_SCHEMA = {
    "verdict": "true_positive | false_positive | uncertain",
    "severity": "P1 | P2 | P3 | P4 | none",
    "attack_tactic": "one of the MITRE ATT&CK tactic names, or None",
    "likely_cause": "one short sentence",
    "recommended_next_step": "one concrete analyst action",
    "confidence": "float between 0 and 1",
    "rationale": "one or two sentences citing the evidence",
}


def build_prompt(alert: dict[str, Any], enrichment: dict[str, Any]) -> str:
    return (
        "Triage this security alert. Use the enrichment results; do not invent "
        "evidence that is not present. If the context is insufficient, return "
        "verdict 'uncertain' with low confidence rather than guessing.\n\n"
        f"ALERT:\n{json.dumps(alert, indent=2)}\n\n"
        f"ENRICHMENT (local tools):\n{json.dumps(enrichment, indent=2)}\n\n"
        f"Return JSON with exactly these fields:\n{json.dumps(OUTPUT_SCHEMA, indent=2)}"
    )


def validate_output(result: dict[str, Any]) -> dict[str, Any]:
    missing = set(OUTPUT_SCHEMA) - set(result)
    if missing:
        raise ValueError(f"Model output missing fields: {sorted(missing)}")
    if result["verdict"] not in VERDICTS:
        raise ValueError(f"Bad verdict: {result['verdict']!r}")
    if result["severity"] not in SEVERITIES:
        raise ValueError(f"Bad severity: {result['severity']!r}")
    if result["attack_tactic"] not in TACTICS:
        raise ValueError(f"Bad tactic: {result['attack_tactic']!r}")
    if not (0.0 <= float(result["confidence"]) <= 1.0):
        raise ValueError(f"Confidence out of range: {result['confidence']!r}")
    return result


class TriageAgent:
    def __init__(self, client: ModelClient, threshold: float = CONFIDENCE_THRESHOLD) -> None:
        self.client = client
        self.threshold = threshold

    def triage(self, alert: dict[str, Any]) -> dict[str, Any]:
        enrichment = enrich(alert)
        raw = self.client.triage(alert, enrichment)
        result = validate_output(raw)
        # Guardrail: low confidence or an explicit 'uncertain' never auto-closes.
        result["human_review"] = (
            result["verdict"] == "uncertain" or float(result["confidence"]) < self.threshold
        )
        result["enrichment"] = enrichment
        return result


if __name__ == "__main__":
    demo = {
        "id": "DEMO-001", "source": "identity",
        "title": "Password spray against 12 user accounts",
        "host": "idp.example-corp.local", "user": "multiple-users",
        "indicators": ["203.0.113.66"], "timestamp": "2026-10-04T02:14:00Z",
        "log_snippet": "Password spray pattern: failures for 12 users from 203.0.113.66.",
    }
    agent = TriageAgent(get_model_client("mock"))
    print(json.dumps(agent.triage(demo), indent=2))
