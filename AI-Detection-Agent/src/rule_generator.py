def generate_sigma(alert: dict, scenario: str, mapping: dict, severity: str) -> str:
    title = alert.get("alert_name", scenario.replace("_", " ").title())
    level = severity.lower()
    tag = mapping["technique_id"].lower().replace(".", "_")

    if scenario == "suspicious_powershell":
        detection = """  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
  condition: selection"""
    elif scenario == "impossible_travel":
        detection = """  selection:
    Operation: 'UserLoggedIn'
  timeframe: 30m
  condition: selection"""
    elif scenario == "admin_creation":
        detection = """  selection:
    EventID:
      - 4728
      - 4732
      - 4756
    TargetUserName|contains:
      - 'Administrators'
      - 'Domain Admins'
  condition: selection"""
    elif scenario == "data_exfiltration":
        detection = """  selection:
    EventType: 'FileDownloaded'
  threshold:
    BytesDownloaded|gt: 2147483648
  condition: selection and threshold"""
    elif scenario == "brute_force":
        detection = """  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count(Account) by SourceIp >= 50"""
    else:
        detection = """  selection:
    EventType|exists: true
  condition: selection"""

    return f"""title: {title}
id: generated-{scenario}
status: experimental
description: Detects {title.lower()} activity requiring analyst validation.
author: AI Detection Engineer Agent
date: 2026/07/01
logsource:
  product: windows
detection:
{detection}
falsepositives:
{yaml_list(false_positives_for(scenario))}
level: {level}
tags:
  - attack.{mapping["tactic"].split()[0].lower().replace("/", "")}
  - attack.{tag}
"""


def generate_kql(alert: dict, scenario: str) -> str:
    if scenario == "suspicious_powershell":
        return """DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName"""

    if scenario == "impossible_travel":
        return """SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PreviousCountry = prev(tostring(Location.countryOrRegion)), PreviousTime = prev(TimeGenerated), PreviousUser = prev(UserPrincipalName)
| where UserPrincipalName == PreviousUser and tostring(Location.countryOrRegion) != PreviousCountry
| where datetime_diff("minute", TimeGenerated, PreviousTime) <= 30"""

    if scenario == "admin_creation":
        return """SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4728, 4732, 4756)
| where TargetUserName has_any ("Administrators", "Domain Admins", "Enterprise Admins")
| project TimeGenerated, Computer, Account, TargetUserName, MemberName, Activity"""

    if scenario == "data_exfiltration":
        return """CloudAppEvents
| where TimeGenerated > ago(24h)
| where ActionType has_any ("FileDownloaded", "Download")
| extend BytesDownloaded = tolong(RawEventData.BytesDownloaded)
| summarize TotalBytesDownloaded=sum(BytesDownloaded), FileEvents=count() by AccountDisplayName, Application, bin(TimeGenerated, 1h)
| where TotalBytesDownloaded > 2147483648
| where hourofday(TimeGenerated) < 8 or hourofday(TimeGenerated) > 20"""

    if scenario == "brute_force":
        return """SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedLogons=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Account, IpAddress, Computer
| where FailedLogons >= 50
| order by FailedLogons desc"""

    return """SecurityEvent
| where TimeGenerated > ago(24h)
| take 100"""


def false_positives_for(scenario: str) -> list[str]:
    return {
        "suspicious_powershell": ["Administrative scripts", "Software deployment tooling"],
        "impossible_travel": ["VPN or proxy geolocation", "Shared accounts"],
        "admin_creation": ["Approved help desk change", "Privileged access management workflow"],
        "data_exfiltration": ["Backup or reporting export", "Approved bulk download"],
        "brute_force": ["Expired password retry", "Misconfigured service account"],
        "generic_alert": ["Unknown business context"],
    }[scenario]


def yaml_list(values: list[str]) -> str:
    return "\n".join(f"  - {value}" for value in values)
