from parser import parse_log_file
from detector import run_all_detections
from reporter import (
    generate_summary,
    print_summary,
    export_json_report,
    export_alerts_csv
)


events = parse_log_file("logs/auth.log")

print("=== Parsed Events ===")

for event in events:
    printable_event = event.copy()

    printable_event["timestamp"] = (
        event["timestamp"].strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print(printable_event)


alerts = run_all_detections(events)


print("\n=== Security Alerts ===")

if alerts:
    for alert in alerts:
        print("\n------------------------------")

        print(f"Alert ID: {alert['alert_id']}")
        print(f"Type: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Severity Score: {alert['severity_score']}")

        if alert.get("trusted_ip"):
            print("Trusted IP: Yes")

        if "original_severity" in alert:
            print(
                f"Original Severity: "
                f"{alert['original_severity']}"
            )

        print(f"MITRE Technique: {alert['mitre_id']}")
        print(f"MITRE Name: {alert['mitre_name']}")
        print(f"Source IP: {alert['ip']}")

        if "username" in alert:
            print(f"Username: {alert['username']}")

        if "timestamp" in alert:
            print(f"Timestamp: {alert['timestamp']}")

        if "status" in alert:
            print(f"Status: {alert['status']}")

        if "failed_attempts" in alert:
            print(
                f"Failed Attempts: "
                f"{alert['failed_attempts']}"
            )

        if "previous_failures" in alert:
            print(
                f"Previous Failures: "
                f"{alert['previous_failures']}"
            )

        if "time_window" in alert:
            print(
                f"Time Window: "
                f"{alert['time_window']}"
            )

        if "login_hour" in alert:
            print(
                f"Login Hour: "
                f"{alert['login_hour']}"
            )

        if "unique_users" in alert:
            print(
                f"Unique Targeted Users: "
                f"{alert['unique_users']}"
            )

        if "targeted_users" in alert:
            print(
                f"Targeted Users: "
                f"{', '.join(alert['targeted_users'])}"
            )

        if "unique_source_ips" in alert:
            print(
                f"Unique Source IPs: "
                f"{alert['unique_source_ips']}"
            )

        if "source_ips" in alert:
            print(
                f"Source IPs: "
                f"{', '.join(alert['source_ips'])}"
            )
        if "occurrences" in alert:
         print(f"Occurrences: {alert['occurrences']}")

        if "first_seen" in alert:
            print(f"First Seen: {alert['first_seen']}")

        if "last_seen" in alert:
            print(f"Last Seen: {alert['last_seen']}")    

    print("\n------------------------------")

else:
    print("No threats detected.")


summary = generate_summary(events, alerts)

print_summary(summary)

export_json_report(
    events,
    alerts,
    summary
)

export_alerts_csv(alerts)