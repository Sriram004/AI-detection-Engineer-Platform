MITRE_MAPPINGS = {
    "suspicious_powershell": {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "reference": "https://attack.mitre.org/techniques/T1059/001/",
        "rationale": "The alert contains PowerShell execution with encoded command content, which maps to PowerShell-based command execution.",
    },
    "impossible_travel": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "reference": "https://attack.mitre.org/techniques/T1078/",
        "rationale": "Successful authentication from impossible locations suggests use of valid but potentially compromised credentials.",
    },
    "admin_creation": {
        "tactic": "Persistence / Privilege Escalation",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "reference": "https://attack.mitre.org/techniques/T1098/",
        "rationale": "Adding an account to an administrators group is account manipulation that may grant persistent privileged access.",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "reference": "https://attack.mitre.org/techniques/T1048/",
        "rationale": "Large off-hours data transfer can indicate data exfiltration over network services or alternative protocols.",
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "reference": "https://attack.mitre.org/techniques/T1110/",
        "rationale": "Many failed logons in a short period are consistent with password guessing or credential stuffing.",
    },
    "generic_alert": {
        "tactic": "Discovery",
        "technique_id": "Unknown",
        "technique_name": "Requires analyst review",
        "reference": "https://attack.mitre.org/",
        "rationale": "The alert lacks enough normalized fields to map confidently to a single ATT&CK technique.",
    },
}


def map_attack(alert: dict, scenario: str) -> dict:
    return MITRE_MAPPINGS.get(scenario, MITRE_MAPPINGS["generic_alert"])
