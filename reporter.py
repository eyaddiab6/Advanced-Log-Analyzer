import json
import os
import csv
from collections import Counter


def generate_summary(events, alerts):
    total_events = len(events)

    successful_logins = sum(
        1 for event in events
        if event["status"] == "success"
    )

    failed_logins = sum(
        1 for event in events
        if event["status"] == "failed"
    )

    severity_counts = Counter(
        alert["severity"] for alert in alerts
    )

    total_alert_occurrences = sum(
        alert.get("occurrences", 1)
        for alert in alerts
    )

    alert_ip_counts = Counter()

    for alert in alerts:
        ip = alert.get("ip")

        if not ip or ip == "multiple":
            continue

        alert_ip_counts[ip] += alert.get(
            "occurrences",
            1
        )

    targeted_users = Counter(
        event["username"]
        for event in events
        if event["status"] == "failed"
    )

    mitre_counts = Counter()

    for alert in alerts:
        key = (
            alert["mitre_id"],
            alert["mitre_name"]
        )

        mitre_counts[key] += alert.get(
            "occurrences",
            1
        )

    top_suspicious_ip = None
    top_suspicious_ip_alerts = 0

    if alert_ip_counts:
        top_suspicious_ip, top_suspicious_ip_alerts = (
            alert_ip_counts.most_common(1)[0]
        )

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,

        "unique_alerts": len(alerts),
        "total_alert_occurrences": total_alert_occurrences,

        "critical_alerts": severity_counts.get(
            "CRITICAL",
            0
        ),
        "high_alerts": severity_counts.get(
            "HIGH",
            0
        ),
        "medium_alerts": severity_counts.get(
            "MEDIUM",
            0
        ),
        "low_alerts": severity_counts.get(
            "LOW",
            0
        ),

        "top_suspicious_ip": top_suspicious_ip,
        "top_suspicious_ip_alerts": (
            top_suspicious_ip_alerts
        ),

        "top_attacking_ips": (
            alert_ip_counts.most_common()
        ),

        "most_targeted_users": (
            targeted_users.most_common()
        ),

        "mitre_summary": [
            {
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "alerts": count
            }
            for (
                mitre_id,
                mitre_name
            ), count
            in mitre_counts.most_common()
        ]
    }


def print_summary(summary):
    print("\n=== Security Summary ===")

    print(
        f"Total Events: "
        f"{summary['total_events']}"
    )

    print(
        f"Successful Logins: "
        f"{summary['successful_logins']}"
    )

    print(
        f"Failed Logins: "
        f"{summary['failed_logins']}"
    )

    print(
        f"Unique Alerts: "
        f"{summary['unique_alerts']}"
    )

    print(
        f"Total Alert Occurrences: "
        f"{summary['total_alert_occurrences']}"
    )

    print("\n=== Alerts by Severity ===")

    print(
        f"Critical: "
        f"{summary['critical_alerts']}"
    )

    print(
        f"High: "
        f"{summary['high_alerts']}"
    )

    print(
        f"Medium: "
        f"{summary['medium_alerts']}"
    )

    print(
        f"Low: "
        f"{summary['low_alerts']}"
    )

    print("\n=== Top Suspicious IP ===")

    if summary["top_suspicious_ip"]:
        print(
            f"IP: "
            f"{summary['top_suspicious_ip']}"
        )

        print(
            f"Triggered Alert Occurrences: "
            f"{summary['top_suspicious_ip_alerts']}"
        )

    else:
        print(
            "No suspicious IPs detected."
        )

    print("\n=== Top Attacking IPs ===")

    if summary["top_attacking_ips"]:
        for ip, count in summary[
            "top_attacking_ips"
        ]:
            print(
                f"{ip} -> "
                f"{count} alert occurrence(s)"
            )
    else:
        print(
            "No attacking IPs detected."
        )

    print("\n=== Most Targeted Users ===")

    if summary["most_targeted_users"]:
        for username, count in summary[
            "most_targeted_users"
        ]:
            print(
                f"{username} -> "
                f"{count} failed attempt(s)"
            )
    else:
        print(
            "No targeted users detected."
        )

    print("\n=== MITRE ATT&CK Summary ===")

    if summary["mitre_summary"]:
        for technique in summary[
            "mitre_summary"
        ]:
            print(
                f"{technique['mitre_id']} - "
                f"{technique['mitre_name']} "
                f"-> {technique['alerts']} "
                f"alert occurrence(s)"
            )
    else:
        print(
            "No MITRE techniques detected."
        )


def export_json_report(
    events,
    alerts,
    summary,
    file_path="reports/security_report.json"
):
    report = {
        "events": events,
        "alerts": alerts,
        "summary": summary
    }

    directory = os.path.dirname(
        file_path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        file_path,
        "w"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            default=str
        )

    print(
        f"\nJSON report exported to: "
        f"{file_path}"
    )


def export_alerts_csv(
    alerts,
    file_path="reports/alerts.csv"
):
    directory = os.path.dirname(
        file_path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    fieldnames = [
        "alert_id",
        "type",
        "severity",
        "severity_score",
        "trusted_ip",
        "original_severity",
        "mitre_id",
        "mitre_name",
        "ip",
        "username",
        "timestamp",
        "status",
        "failed_attempts",
        "previous_failures",
        "time_window",
        "login_hour",
        "unique_users",
        "targeted_users",
        "unique_source_ips",
        "source_ips",
        "occurrences",
        "first_seen",
        "last_seen"
    ]

    with open(
        file_path,
        "w",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for alert in alerts:
            row = {
                field: alert.get(
                    field,
                    ""
                )
                for field in fieldnames
            }

            if isinstance(
                row.get("targeted_users"),
                list
            ):
                row["targeted_users"] = (
                    ", ".join(
                        row["targeted_users"]
                    )
                )

            if isinstance(
                row.get("source_ips"),
                list
            ):
                row["source_ips"] = (
                    ", ".join(
                        row["source_ips"]
                    )
                )

            writer.writerow(row)

    print(
        f"CSV alerts exported to: "
        f"{file_path}"
    )