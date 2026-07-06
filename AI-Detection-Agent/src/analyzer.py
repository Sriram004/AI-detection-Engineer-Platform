import json
import os
from pathlib import Path
from typing import Any

from .mitre_mapper import map_attack
from .rule_generator import generate_kql, generate_sigma


def load_alert(source: Any) -> dict:
    if hasattr(source, "read"):
        raw = source.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    with open(source, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def load_sample_alerts(alert_dir: Path) -> dict[str, dict]:
    alerts = {}
    for path in sorted(alert_dir.glob("*.json")):
        alerts[path.stem.replace("_", " ").title()] = load_alert(path)
    return alerts


def analyze_alert(alert: dict, use_openai: bool = False) -> dict:
    scenario = classify_alert(alert)
    mapping = map_attack(alert, scenario)
    severity = severity_for(scenario)
    confidence = confidence_for(alert, scenario)

    analysis = {
        "scenario": scenario,
        "alert_name": alert.get("alert_name", scenario.replace("_", " ").title()),
        "investigation_summary": build_summary(alert, scenario),
        "attack_hypothesis": build_hypothesis(scenario),
        "mitre_mapping": mapping,
        "severity": severity,
        "confidence": confidence,
        "false_positive_considerations": false_positives_for(scenario),
        "response_steps": response_steps_for(scenario),
        "sigma_rule": generate_sigma(alert, scenario, mapping, severity),
        "kql_rule": generate_kql(alert, scenario),
    }

    if use_openai:
        analysis["openai_enrichment"] = optional_openai_enrichment(alert, analysis)

    return analysis


def classify_alert(alert: dict) -> str:
    text = json.dumps(alert, default=str).lower()
    if "encodedcommand" in text or ("powershell" in text and "encoded" in text):
        return "suspicious_powershell"
    if "impossible" in text or ("india" in text and "germany" in text):
        return "impossible_travel"
    if "4728" in text or "4732" in text or "administrators" in text or "domain admins" in text:
        return "admin_creation"
    if "download" in text or "exfil" in text or "bytes_downloaded" in text:
        return "data_exfiltration"
    if "4625" in text or "failed_count" in text or "brute" in text:
        return "brute_force"
    return "generic_alert"


def build_summary(alert: dict, scenario: str) -> str:
    host = alert.get("hostname") or alert.get("host") or "unknown host"
    user = alert.get("user") or alert.get("account") or alert.get("user_principal_name") or "unknown user"
    summaries = {
        "suspicious_powershell": f"{user} executed PowerShell on {host} with an encoded command line. Encoded PowerShell is commonly used to hide payloads, downloaders, credential theft tooling, or post-exploitation commands.",
        "impossible_travel": f"{user} authenticated from geographically distant countries within a short time window. The login pattern is not physically plausible and may indicate credential compromise.",
        "admin_creation": f"{user} or an associated actor modified an administrators group on {host}. New privileged access can indicate persistence or privilege escalation.",
        "data_exfiltration": f"{user} downloaded an unusually large amount of data outside normal business hours. The behavior may represent staging or exfiltration.",
        "brute_force": f"{user} generated a high volume of failed login attempts in a short period. This pattern is consistent with password guessing or credential stuffing.",
        "generic_alert": f"Alert involving {user} on {host} requires triage because it did not match a known built-in scenario.",
    }
    return summaries[scenario]


def build_hypothesis(scenario: str) -> str:
    hypotheses = {
        "suspicious_powershell": "An attacker may be using PowerShell for execution, defense evasion, payload delivery, or credential access after gaining code execution on the endpoint.",
        "impossible_travel": "A valid account may be compromised and reused from an attacker-controlled location or anonymizing infrastructure.",
        "admin_creation": "An attacker may be establishing persistence or escalating privileges by adding a controlled account to an administrative group.",
        "data_exfiltration": "A user or compromised account may be collecting and exfiltrating sensitive files outside approved access patterns.",
        "brute_force": "An attacker may be attempting to guess credentials or validate a password list against a user account.",
        "generic_alert": "Suspicious behavior is present but requires analyst context to determine the attack path.",
    }
    return hypotheses[scenario]


def severity_for(scenario: str) -> str:
    return {
        "suspicious_powershell": "High",
        "impossible_travel": "High",
        "admin_creation": "High",
        "data_exfiltration": "High",
        "brute_force": "Medium",
        "generic_alert": "Medium",
    }[scenario]


def confidence_for(alert: dict, scenario: str) -> int:
    evidence_count = len([value for value in alert.values() if value not in (None, "", [])])
    base = {
        "suspicious_powershell": 86,
        "impossible_travel": 82,
        "admin_creation": 88,
        "data_exfiltration": 80,
        "brute_force": 84,
        "generic_alert": 55,
    }[scenario]
    return min(96, base + min(evidence_count, 5))


def false_positives_for(scenario: str) -> list[str]:
    return {
        "suspicious_powershell": [
            "Administrative scripts can use encoded PowerShell for compatibility.",
            "Software deployment tools may launch PowerShell through trusted parent processes.",
        ],
        "impossible_travel": [
            "VPN, proxy, mobile carrier routing, and cloud security brokers can alter geolocation.",
            "Shared or service accounts may appear in multiple countries.",
        ],
        "admin_creation": [
            "Approved help desk access changes can create expected group modification events.",
            "Identity lifecycle automation may add temporary privileged access.",
        ],
        "data_exfiltration": [
            "Backup jobs, reporting exports, and legitimate data science workflows can move large files.",
            "Time-zone differences can make normal activity appear out of hours.",
        ],
        "brute_force": [
            "Expired passwords, mobile sync clients, and mapped drives can generate repeated failures.",
            "Vulnerability scanners may trigger authentication failures during testing.",
        ],
        "generic_alert": ["Insufficient scenario context can increase analyst review requirements."],
    }[scenario]


def response_steps_for(scenario: str) -> list[str]:
    return {
        "suspicious_powershell": [
            "Collect full process tree, command line, script block logs, and parent process details.",
            "Check endpoint protection alerts and quarantine status.",
            "Review network connections and downloaded files around execution time.",
            "Isolate the endpoint if payload execution or lateral movement is confirmed.",
        ],
        "impossible_travel": [
            "Confirm IP geolocation, VPN use, device identity, and MFA result.",
            "Reset password and revoke sessions if compromise is suspected.",
            "Review mailbox rules, OAuth grants, and recent privileged actions.",
            "Hunt for the same IPs across other accounts.",
        ],
        "admin_creation": [
            "Identify the actor, target account, group name, and approving change ticket.",
            "Remove unauthorized privileged membership.",
            "Review adjacent account management events and logon activity.",
            "Check for persistence actions such as scheduled tasks, services, or new credentials.",
        ],
        "data_exfiltration": [
            "Identify files accessed, destination IPs, application, and business justification.",
            "Preserve access logs and endpoint telemetry.",
            "Disable account or block destination if exfiltration is likely.",
            "Notify data owner and incident response lead.",
        ],
        "brute_force": [
            "Identify source IPs, affected accounts, and success after failure.",
            "Block malicious sources and enforce MFA where available.",
            "Reset affected credentials if a successful login followed the failures.",
            "Tune thresholds by account type and source reputation.",
        ],
        "generic_alert": [
            "Gather surrounding logs and user context.",
            "Confirm whether behavior is approved, expected, or suspicious.",
            "Create a focused hunt query after evidence is clarified.",
        ],
    }[scenario]


def optional_openai_enrichment(alert: dict, local_analysis: dict) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "OpenAI enrichment skipped because OPENAI_API_KEY is not configured."

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        model = os.getenv("OPENAI_MODEL", "gpt-5")
        prompt = (
            "You are a SOC Detection Engineer. Review the alert and local analysis. "
            "Add concise analyst validation advice, false positive notes, and detection tuning recommendations. "
            "Do not approve deployment without human validation.\n\n"
            f"Alert:\n{json.dumps(alert, indent=2)}\n\n"
            f"Local analysis:\n{json.dumps(local_analysis, indent=2)}"
        )
        response = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": "You assist security analysts and require human validation."},
                {"role": "user", "content": prompt},
            ],
        )
        return response.output_text
    except Exception as exc:
        return f"OpenAI enrichment failed gracefully: {exc}"

