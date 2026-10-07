# Active Directory Event Detections

[![CI](https://github.com/nicolasferrerm/active-directory-monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/nicolasferrerm/active-directory-monitoring/actions/workflows/ci.yml)

A defensive Active Directory monitoring project that turns selected Windows Security events into explainable, ATT&CK-mapped alerts. It focuses on identity events with high analyst value and keeps collection separate from detection.

## Detection coverage

| Event | Detection | ATT&CK |
|---:|---|---|
| 1102 | Domain controller audit log cleared | T1070.001 |
| 4728 / 4732 / 4756 | Member added to privileged group | T1098 |
| 4768 | Kerberos request without pre-authentication | T1558.004 |
| 4769 | Kerberos service ticket using RC4 | T1558.003 |

These events are investigative signals, not automatic proof of compromise. Baselines, approved changes, service-account context, and correlated endpoint/network evidence are required during triage.

## Run with synthetic data

```bash
python -m pip install -e .
ad-monitor sample-data/events.jsonl
python -m pytest -q
```

The PowerShell collector exports a bounded set of event records from an authorized Windows host. The Python detector consumes normalized JSONL so tests and demonstrations remain safe and platform-independent.

## Roadmap

- Add Sigma equivalents and SIEM queries for Microsoft Sentinel, Splunk, and Elastic.
- Add allow-listed change windows and service-account baselines.
- Add correlation for repeated ticket requests and privileged-account anomalies.

## Author

Nicolas Ferrer — Information Systems Security student at SAIT and CyberGuardians Club president, focused on identity security and SOC operations.
