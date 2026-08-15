from collections import defaultdict
from datetime import datetime
import json


def load_config(file_path="config.json"):
    with open(file_path, "r") as file:
        return json.load(file)


def detect_brute_force(events, threshold=3, time_window=60):
    failed_attempts = defaultdict(list)
    alerts = []

    for event in events:
        if event["status"] != "failed":
            continue

        key = (
            event["ip"],
            event["username"]
        )

        failed_attempts[key].append(
            event["timestamp"]
        )

    for (ip, username), timestamps in failed_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            attempts = 1

            for j in range(i + 1, len(timestamps)):
                difference = (
                    timestamps[j] - timestamps[i]
                ).total_seconds()

                if difference <= time_window:
                    attempts += 1
                else:
                    break

            if attempts >= threshold:
                alerts.append({
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "username": username,
                    "failed_attempts": attempts,
                    "time_window": f"{time_window} seconds",
                    "severity": "HIGH",
                    "mitre_id": "T1110.001",
                    "mitre_name": "Password Guessing"
                })

                break

    return alerts


def detect_success_after_failures(
    events,
    threshold=3,
    time_window=120
):
    alerts = []

    for i, event in enumerate(events):
        if event["status"] != "success":
            continue

        success_time = event["timestamp"]
        ip = event["ip"]
        username = event["username"]

        failed_count = 0

        for previous_event in events[:i]:
            if (
                previous_event["ip"] == ip
                and previous_event["username"] == username
                and previous_event["status"] == "failed"
            ):
                failed_time = previous_event["timestamp"]

                difference = (
                    success_time - failed_time
                ).total_seconds()

                if 0 <= difference <= time_window:
                    failed_count += 1

        if failed_count >= threshold:
            alerts.append({
                "type": "Successful Login After Multiple Failures",
                "ip": ip,
                "username": username,
                "previous_failures": failed_count,
                "time_window": f"{time_window} seconds",
                "severity": "CRITICAL",
                "mitre_id": "T1078",
                "mitre_name": "Valid Accounts"
            })

    return alerts


def detect_root_login_attempts(events):
    alerts = []

    for event in events:
        if event["username"].lower() != "root":
            continue

        severity = "HIGH"

        if event["status"] == "success":
            severity = "CRITICAL"

        alerts.append({
            "type": "Root Login Attempt",
            "ip": event["ip"],
            "username": event["username"],
            "status": event["status"],
            "timestamp": event["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "severity": severity,
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts"
        })

    return alerts


def detect_off_hours_login(
    events,
    start_hour=0,
    end_hour=5
):
    alerts = []

    for event in events:
        if event["status"] != "success":
            continue

        event_time = event["timestamp"]
        hour = event_time.hour

        if start_hour <= hour < end_hour:
            alerts.append({
                "type": "Off-Hours Login",
                "ip": event["ip"],
                "username": event["username"],
                "timestamp": event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "login_hour": hour,
                "severity": "MEDIUM",
                "mitre_id": "T1078",
                "mitre_name": "Valid Accounts"
            })

    return alerts


def detect_password_spraying(
    events,
    user_threshold=3,
    time_window=120
):
    alerts = []

    failed_events_by_ip = defaultdict(list)

    for event in events:
        if event["status"] != "failed":
            continue

        failed_events_by_ip[event["ip"]].append(event)

    for ip, failed_events in failed_events_by_ip.items():
        failed_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(failed_events)):
            usernames = set()
            first_time = failed_events[i]["timestamp"]

            for j in range(i, len(failed_events)):
                current_event = failed_events[j]

                difference = (
                    current_event["timestamp"] - first_time
                ).total_seconds()

                if difference > time_window:
                    break

                usernames.add(
                    current_event["username"]
                )

            if len(usernames) >= user_threshold:
                alerts.append({
                    "type": "Password Spraying Attack",
                    "ip": ip,
                    "targeted_users": sorted(usernames),
                    "unique_users": len(usernames),
                    "time_window": f"{time_window} seconds",
                    "severity": "HIGH",
                    "mitre_id": "T1110.003",
                    "mitre_name": "Password Spraying"
                })

                break

    return alerts


def detect_targeted_account(
    events,
    ip_threshold=3,
    time_window=300
):
    alerts = []

    failed_events_by_user = defaultdict(list)

    for event in events:
        if event["status"] != "failed":
            continue

        failed_events_by_user[
            event["username"]
        ].append(event)

    for username, failed_events in failed_events_by_user.items():
        failed_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(failed_events)):
            source_ips = set()
            first_time = failed_events[i]["timestamp"]

            for j in range(i, len(failed_events)):
                current_event = failed_events[j]

                difference = (
                    current_event["timestamp"] - first_time
                ).total_seconds()

                if difference > time_window:
                    break

                source_ips.add(
                    current_event["ip"]
                )

            if len(source_ips) >= ip_threshold:
                alerts.append({
                    "type": "Targeted Account Attack",
                    "username": username,
                    "ip": "multiple",
                    "source_ips": sorted(source_ips),
                    "unique_source_ips": len(source_ips),
                    "time_window": f"{time_window} seconds",
                    "severity": "HIGH",
                    "mitre_id": "T1110",
                    "mitre_name": "Brute Force"
                })

                break

    return alerts


def parse_alert_timestamp(timestamp):
    if isinstance(timestamp, datetime):
        return timestamp

    if isinstance(timestamp, str):
        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    return None


def format_alert_timestamp(timestamp):
    if isinstance(timestamp, datetime):
        return timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    return timestamp


def aggregate_alerts(alerts, time_window=600):
    aggregated_alerts = []

    for alert in alerts:
        current_alert = alert.copy()
        current_alert["occurrences"] = 1

        current_timestamp = None

        if "timestamp" in current_alert:
            current_timestamp = parse_alert_timestamp(
                current_alert["timestamp"]
            )

            timestamp_string = format_alert_timestamp(
                current_alert["timestamp"]
            )

            current_alert["timestamp"] = timestamp_string
            current_alert["first_seen"] = timestamp_string
            current_alert["last_seen"] = timestamp_string

        matched_alert = None

        for existing_alert in aggregated_alerts:
            same_type = (
                existing_alert.get("type")
                == current_alert.get("type")
            )

            same_ip = (
                existing_alert.get("ip")
                == current_alert.get("ip")
            )

            same_username = (
                existing_alert.get("username")
                == current_alert.get("username")
            )

            if not (
                same_type
                and same_ip
                and same_username
            ):
                continue

            if current_timestamp is None:
                matched_alert = existing_alert
                break

            if "last_seen" not in existing_alert:
                continue

            last_seen = parse_alert_timestamp(
                existing_alert["last_seen"]
            )

            if last_seen is None:
                continue

            difference = (
                current_timestamp - last_seen
            ).total_seconds()

            if 0 <= difference <= time_window:
                matched_alert = existing_alert
                break

        if matched_alert:
            matched_alert["occurrences"] += 1

            if current_timestamp is not None:
                matched_alert["last_seen"] = (
                    format_alert_timestamp(
                        current_timestamp
                    )
                )

        else:
            aggregated_alerts.append(
                current_alert
            )

    return aggregated_alerts


def apply_trusted_ip_reduction(
    alerts,
    trusted_ips
):
    severity_levels = {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "LOW"
    }

    for alert in alerts:
        ip = alert.get("ip")

        if ip in trusted_ips:
            alert["trusted_ip"] = True
            alert["original_severity"] = (
                alert["severity"]
            )

            alert["severity"] = (
                severity_levels.get(
                    alert["severity"],
                    alert["severity"]
                )
            )
        else:
            alert["trusted_ip"] = False

    return alerts


def add_alert_metadata(alerts):
    severity_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    for index, alert in enumerate(
        alerts,
        start=1
    ):
        alert["alert_id"] = (
            f"ALERT-{index:03d}"
        )

        alert["severity_score"] = (
            severity_order.get(
                alert["severity"],
                0
            )
        )

    return alerts


def run_all_detections(
    events,
    config_path="config.json"
):
    alerts = []

    config = load_config(config_path)

    brute_force_config = config["brute_force"]

    success_config = (
        config["success_after_failures"]
    )

    spraying_config = (
        config["password_spraying"]
    )

    targeted_config = (
        config["targeted_account"]
    )

    off_hours_config = (
        config["off_hours"]
    )

    root_login_config = (
        config["root_login"]
    )

    if targeted_config["enabled"]:
        alerts.extend(
            detect_targeted_account(
                events,
                ip_threshold=(
                    targeted_config[
                        "ip_threshold"
                    ]
                ),
                time_window=(
                    targeted_config[
                        "time_window"
                    ]
                )
            )
        )

    if brute_force_config["enabled"]:
        alerts.extend(
            detect_brute_force(
                events,
                threshold=(
                    brute_force_config[
                        "threshold"
                    ]
                ),
                time_window=(
                    brute_force_config[
                        "time_window"
                    ]
                )
            )
        )

    if success_config["enabled"]:
        alerts.extend(
            detect_success_after_failures(
                events,
                threshold=(
                    success_config[
                        "threshold"
                    ]
                ),
                time_window=(
                    success_config[
                        "time_window"
                    ]
                )
            )
        )

    if root_login_config["enabled"]:
        alerts.extend(
            detect_root_login_attempts(
                events
            )
        )

    if off_hours_config["enabled"]:
        alerts.extend(
            detect_off_hours_login(
                events,
                start_hour=(
                    off_hours_config[
                        "start_hour"
                    ]
                ),
                end_hour=(
                    off_hours_config[
                        "end_hour"
                    ]
                )
            )
        )

    if spraying_config["enabled"]:
        alerts.extend(
            detect_password_spraying(
                events,
                user_threshold=(
                    spraying_config[
                        "user_threshold"
                    ]
                ),
                time_window=(
                    spraying_config[
                        "time_window"
                    ]
                )
            )
        )

    trusted_ips = config.get(
        "trusted_ips",
        []
    )

    alerts = apply_trusted_ip_reduction(
        alerts,
        trusted_ips
    )

    aggregation_config = config.get(
        "aggregation",
        {}
    )

    aggregation_window = (
        aggregation_config.get(
            "time_window",
            600
        )
    )

    alerts = aggregate_alerts(
        alerts,
        time_window=aggregation_window
    )

    alerts = add_alert_metadata(
        alerts
    )

    return alerts