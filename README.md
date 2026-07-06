# AI Detection Engineer Agent

AI Detection Engineer Agent is a portfolio-ready SOC investigation and detection engineering project. It accepts a security alert, summarizes the activity, maps it to MITRE ATT&CK, generates Sigma and Microsoft Sentinel KQL rules, stores analyst validation, and exports an incident report.

Workflow:

```text
Alert -> AI-assisted analysis -> MITRE ATT&CK mapping -> detection rule -> analyst validation -> report
```

## Features

- Analyze five common SOC scenarios: suspicious encoded PowerShell, impossible travel, new local administrator, large data download, and multiple failed logins.
- Generate investigation summaries, attack hypotheses, MITRE mappings, response steps, Sigma rules, and KQL queries.
- Run fully offline with deterministic detection engineering logic.
- Optionally call OpenAI when `OPENAI_API_KEY` is configured.
- Save incidents, validation decisions, analyst notes, generated rules, and markdown reports.
- Use a Streamlit dashboard for upload, review, validation, and export.
- Expose a small FastAPI endpoint for programmatic analysis.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## Optional OpenAI Setup

Copy `.env.example` to `.env` and add your key:

```text
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-5
```

In the dashboard, enable **Use OpenAI enrichment** before analyzing. If no key is configured, the app still produces a complete local analysis.

## Run The API

```powershell
uvicorn api:app --reload
```

## Run Tests

```powershell
python -m unittest discover -s tests
```

## Analyst Validation Checklist

Before approving generated detection content, validate:

- MITRE technique and tactic fit the observed behavior.
- Sigma fields match the actual log source.
- KQL table and field names match your Sentinel workspace.
- False positives are understood and documented.
- Response steps are appropriate for the severity.
- The rule has been tested against sample benign and suspicious events.
