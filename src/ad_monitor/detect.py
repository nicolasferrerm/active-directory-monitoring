from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
}


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre_attack: str
    event_id: int
    account: str
    reason: str


def detect(records: Iterable[dict[str, object]]) -> list[Alert]:
    alerts: list[Alert] = []
    for record in records:
        event_id = int(record["event_id"])
        account = str(record.get("account", "unknown"))
        group = str(record.get("group", "")).lower()
        encryption_type = str(record.get("encryption_type", "")).lower()
        preauth_type = str(record.get("preauth_type", ""))

        if event_id == 1102:
            alerts.append(
                Alert(
                    "AD-LOG-001",
                    "Domain controller audit log cleared",
                    "critical",
                    "T1070.001",
                    event_id,
                    account,
                    "Security log clearing removes evidence and requires immediate validation.",
                )
            )
        elif event_id in {4728, 4732, 4756} and group in PRIVILEGED_GROUPS:
            alerts.append(
                Alert(
                    "AD-GROUP-001",
                    "Member added to privileged group",
                    "high",
                    "T1098",
                    event_id,
                    account,
                    f"Membership changed for privileged group: {group}.",
                )
            )
        elif event_id == 4768 and preauth_type == "0":
            alerts.append(
                Alert(
                    "AD-KRB-001",
                    "Kerberos ticket requested without pre-authentication",
                    "high",
                    "T1558.004",
                    event_id,
                    account,
                    "Pre-authentication type 0 may expose an account to AS-REP roasting.",
                )
            )
        elif event_id == 4769 and encryption_type in {"0x17", "23", "rc4"}:
            alerts.append(
                Alert(
                    "AD-KRB-002",
                    "Kerberos service ticket used RC4",
                    "medium",
                    "T1558.003",
                    event_id,
                    account,
                    "RC4 service tickets warrant review for legacy configuration or Kerberoasting.",
                )
            )

    return alerts
