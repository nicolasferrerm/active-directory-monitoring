from ad_monitor.detect import detect


def test_high_value_ad_events_are_mapped():
    alerts = detect(
        [
            {"event_id": 4768, "account": "legacy", "preauth_type": "0"},
            {"event_id": 4769, "account": "svc-web", "encryption_type": "0x17"},
            {"event_id": 4728, "account": "alice", "group": "Domain Admins"},
            {"event_id": 1102, "account": "SYSTEM"},
        ]
    )

    assert [alert.rule_id for alert in alerts] == [
        "AD-KRB-001",
        "AD-KRB-002",
        "AD-GROUP-001",
        "AD-LOG-001",
    ]


def test_normal_logon_and_non_privileged_group_change_do_not_alert():
    alerts = detect(
        [
            {"event_id": 4624, "account": "alice"},
            {"event_id": 4728, "account": "bob", "group": "Help Desk"},
        ]
    )

    assert alerts == []
