import json
from pathlib import Path


def export_report(root: Path, incident_id: int, alert: dict, analysis: dict, validation: dict) -> Path:
    report_dir = root / "reports"
    sigma_dir = root / "rules" / "sigma"
    kql_dir = root / "rules" / "sentinel"
    report_dir.mkdir(parents=True, exist_ok=True)
    sigma_dir.mkdir(parents=True, exist_ok=True)
    kql_dir.mkdir(parents=True, exist_ok=True)

    slug = analysis["alert_name"].lower().replace(" ", "_").replace("/", "_")
    sigma_path = sigma_dir / f"{incident_id}_{slug}.yml"
    kql_path = kql_dir / f"{incident_id}_{slug}.kql"
    report_path = report_dir / f"incident_{incident_id}_{slug}.md"

    sigma_path.write_text(analysis["sigma_rule"], encoding="utf-8")
    kql_path.write_text(analysis["kql_rule"], encoding="utf-8")
    report_path.write_text(render_report(incident_id, alert, analysis, validation, sigma_path, kql_path), encoding="utf-8")
    return report_path


def render_report(incident_id: int, alert: dict, analysis: dict, validation: dict, sigma_path: Path, kql_path: Path) -> str:
    mapping = analysis["mitre_mapping"]
    response_steps = "\n".join(f"- {step}" for step in analysis["response_steps"])
    false_positives = "\n".join(f"- {item}" for item in analysis["false_positive_considerations"])

    return f"""# Incident Report {incident_id}: {analysis["alert_name"]}

## Incident Summary

{analysis["investigation_summary"]}

## Alert Details

```json
{json.dumps(alert, indent=2)}
```

## Attack Hypothesis

{analysis["attack_hypothesis"]}

## MITRE ATT&CK Mapping

- Tactic: {mapping["tactic"]}
- Technique: {mapping["technique_id"]} - {mapping["technique_name"]}
- Rationale: {mapping["rationale"]}
- Reference: {mapping["reference"]}

## Detection Content

- Sigma rule: `{sigma_path}`
- Microsoft Sentinel KQL: `{kql_path}`

## Response Steps

{response_steps}

## False Positive Considerations

{false_positives}

## Analyst Validation

- Analyst: {validation.get("analyst", "Unknown")}
- Decision: {validation.get("status", "Needs Review")}
- MITRE validated: {validation.get("mitre_ok", False)}
- Logic validated: {validation.get("logic_ok", False)}
- False positives reviewed: {validation.get("false_positives_ok", False)}
- Response validated: {validation.get("response_ok", False)}

## Analyst Notes

{validation.get("notes", "")}
"""
