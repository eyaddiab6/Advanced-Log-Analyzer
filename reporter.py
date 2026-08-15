import json
import os
import csv
from collections import Counter


def generate_summary(events, alerts):
    total_events = len(events)

    ssh_events = [
        event
        for event in events
        if event.get("event_type") == "ssh_login"
    ]

    web_events = [
        event
        for event in events
        if event.get("event_type") == "http_request"
    ]

    successful_logins = sum(
        1
        for event in ssh_events
        if event.get("status") == "success"
    )

    failed_logins = sum(
        1
        for event in ssh_events
        if event.get("status") == "failed"
    )

    severity_counts = Counter(
        alert.get("severity", "UNKNOWN")
        for alert in alerts
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
        event.get("username")
        for event in ssh_events
        if (
            event.get("status") == "failed"
            and event.get("username")
        )
    )

    mitre_counts = Counter()

    for alert in alerts:
        mitre_id = alert.get("mitre_id")
        mitre_name = alert.get("mitre_name")

        if not mitre_id:
            continue

        key = (
            mitre_id,
            mitre_name or "Unknown"
        )

        mitre_counts[key] += alert.get(
            "occurrences",
            1
        )

    top_suspicious_ip = None
    top_suspicious_ip_alerts = 0

    if alert_ip_counts:
        (
            top_suspicious_ip,
            top_suspicious_ip_alerts
        ) = alert_ip_counts.most_common(1)[0]

    highest_risk_alert = None

    if alerts:
        highest_risk_alert = max(
            alerts,
            key=lambda alert: alert.get(
                "risk_score",
                0
            )
        )

    source_counts = Counter(
        event.get("source_type", "unknown")
        for event in events
    )

    http_method_counts = Counter(
        event.get("method")
        for event in web_events
        if event.get("method")
    )

    http_status_counts = Counter(
        event.get("status_code")
        for event in web_events
        if event.get("status_code") is not None
    )

    requested_paths = Counter(
        event.get("path")
        for event in web_events
        if event.get("path")
    )

    http_2xx = sum(
        1
        for event in web_events
        if 200 <= event.get("status_code", 0) < 300
    )

    http_3xx = sum(
        1
        for event in web_events
        if 300 <= event.get("status_code", 0) < 400
    )

    http_4xx = sum(
        1
        for event in web_events
        if 400 <= event.get("status_code", 0) < 500
    )

    http_5xx = sum(
        1
        for event in web_events
        if 500 <= event.get("status_code", 0) < 600
    )

    return {
        "total_events": total_events,

        "ssh_events": len(ssh_events),
        "web_events": len(web_events),

        "successful_logins": successful_logins,
        "failed_logins": failed_logins,

        "highest_risk_alert": highest_risk_alert,

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
        ],

        "source_summary": [
            {
                "source": source,
                "events": count
            }
            for source, count
            in source_counts.most_common()
        ],

        "http_method_summary": [
            {
                "method": method,
                "requests": count
            }
            for method, count
            in http_method_counts.most_common()
        ],

        "http_status_summary": [
            {
                "status_code": status_code,
                "requests": count
            }
            for status_code, count
            in http_status_counts.most_common()
        ],

        "top_requested_paths": (
            requested_paths.most_common(10)
        ),

        "http_2xx": http_2xx,
        "http_3xx": http_3xx,
        "http_4xx": http_4xx,
        "http_5xx": http_5xx
    }


def print_summary(summary):
    print("\n=== Security Summary ===")

    print(
        f"Total Events: "
        f"{summary['total_events']}"
    )

    print(
        f"SSH Events: "
        f"{summary['ssh_events']}"
    )

    print(
        f"Web Events: "
        f"{summary['web_events']}"
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

    print("\n=== Web Statistics ===")

    print(
        f"HTTP 2xx: "
        f"{summary['http_2xx']}"
    )

    print(
        f"HTTP 3xx: "
        f"{summary['http_3xx']}"
    )

    print(
        f"HTTP 4xx: "
        f"{summary['http_4xx']}"
    )

    print(
        f"HTTP 5xx: "
        f"{summary['http_5xx']}"
    )

    if summary["http_method_summary"]:
        print("\nHTTP Methods:")

        for item in summary[
            "http_method_summary"
        ]:
            print(
                f"{item['method']} -> "
                f"{item['requests']} request(s)"
            )

    if summary["top_requested_paths"]:
        print("\nTop Requested Paths:")

        for path, count in summary[
            "top_requested_paths"
        ]:
            print(
                f"{path} -> "
                f"{count} request(s)"
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
        "w",
        encoding="utf-8"
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
        "risk_score",
        "risk_level",
        "trusted_ip",
        "original_severity",
        "mitre_id",
        "mitre_name",
        "ip",
        "username",
        "source_type",
        "timestamp",
        "status",

        "method",
        "path",
        "status_code",
        "matched_pattern",

        "failed_attempts",
        "previous_failures",
        "failed_requests",
        "request_count",

        "time_window",
        "login_hour",

        "unique_users",
        "targeted_users",

        "unique_source_ips",
        "source_ips",

        "unique_paths",
        "paths",

        "occurrences",
        "first_seen",
        "last_seen"
    ]

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
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

            list_fields = [
                "targeted_users",
                "source_ips",
                "paths"
            ]

            for field in list_fields:
                if isinstance(
                    row.get(field),
                    list
                ):
                    row[field] = ", ".join(
                        str(item)
                        for item in row[field]
                    )

            writer.writerow(row)

    print(
        f"CSV alerts exported to: "
        f"{file_path}"
    )