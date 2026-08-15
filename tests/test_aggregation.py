from detector import aggregate_alerts


def test_alert_aggregation():
    alerts = [
        {
            "type": "Root Login Attempt",
            "ip": "10.0.0.1",
            "username": "root",
            "timestamp":
                "2026-08-15 12:00:00",
            "severity": "HIGH",
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts"
        },
        {
            "type": "Root Login Attempt",
            "ip": "10.0.0.1",
            "username": "root",
            "timestamp":
                "2026-08-15 12:00:20",
            "severity": "HIGH",
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts"
        }
    ]

    aggregated = aggregate_alerts(
        alerts
    )

    assert len(aggregated) == 1

    assert (
        aggregated[0]["occurrences"]
        == 2
    )

    assert (
        aggregated[0]["first_seen"]
        == "2026-08-15 12:00:00"
    )

    assert (
        aggregated[0]["last_seen"]
        == "2026-08-15 12:00:20"
    )


def test_different_ips_are_not_aggregated():
    alerts = [
        {
            "type": "Root Login Attempt",
            "ip": "10.0.0.1",
            "username": "root",
            "severity": "HIGH",
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts"
        },
        {
            "type": "Root Login Attempt",
            "ip": "10.0.0.2",
            "username": "root",
            "severity": "HIGH",
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts"
        }
    ]

    aggregated = aggregate_alerts(
        alerts
    )

    assert len(aggregated) == 2