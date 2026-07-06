REQUIRED_CHECKS = ["mitre_ok", "logic_ok", "false_positives_ok", "response_ok"]


def validation_score(validation: dict) -> int:
    passed = sum(1 for key in REQUIRED_CHECKS if validation.get(key))
    return int((passed / len(REQUIRED_CHECKS)) * 100)


def final_status(validation: dict) -> str:
    if validation.get("status") == "Rejected":
        return "Rejected"
    if validation.get("status") == "Approved" and validation_score(validation) == 100:
        return "Approved"
    return "Needs Review"
