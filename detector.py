from collections import defaultdict
from datetime import datetime
import json


def load_config(file_path="config.json"):
    with open(file_path, "r") as file:
        return json.load(file)


def is_ssh_event(event):
    return event.get("event_type") == "ssh_login"


def is_web_event(event):
    return event.get("event_type") == "http_request"


# =========================================================
# SSH DETECTIONS
# =========================================================

def detect_brute_force(events, threshold=3, time_window=60):
    failed_attempts = defaultdict(list)
    alerts = []

    for event in events:
        if not is_ssh_event(event):
            continue

        if event.get("status") != "failed":
            continue

        key = (
            event.get("ip"),
            event.get("username")
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

    ssh_events = [
        event
        for event in events
        if is_ssh_event(event)
    ]

    for i, event in enumerate(ssh_events):
        if event.get("status") != "success":
            continue

        success_time = event["timestamp"]
        ip = event.get("ip")
        username = event.get("username")

        failed_count = 0

        for previous_event in ssh_events[:i]:
            if (
                previous_event.get("ip") == ip
                and previous_event.get("username") == username
                and previous_event.get("status") == "failed"
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
        if not is_ssh_event(event):
            continue

        username = event.get("username", "")

        if username.lower() != "root":
            continue

        severity = "HIGH"

        if event.get("status") == "success":
            severity = "CRITICAL"

        alerts.append({
            "type": "Root Login Attempt",
            "ip": event.get("ip"),
            "username": username,
            "status": event.get("status"),
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
        if not is_ssh_event(event):
            continue

        if event.get("status") != "success":
            continue

        event_time = event["timestamp"]
        hour = event_time.hour

        if start_hour <= hour < end_hour:
            alerts.append({
                "type": "Off-Hours Login",
                "ip": event.get("ip"),
                "username": event.get("username"),
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
        if not is_ssh_event(event):
            continue

        if event.get("status") != "failed":
            continue

        failed_events_by_ip[event.get("ip")].append(event)

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
                    current_event.get("username")
                )

            usernames.discard(None)

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
        if not is_ssh_event(event):
            continue

        if event.get("status") != "failed":
            continue

        username = event.get("username")

        if username is None:
            continue

        failed_events_by_user[
            username
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
                    current_event.get("ip")
                )

            source_ips.discard(None)

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


# =========================================================
# WEB DETECTIONS
# =========================================================

def detect_web_path_scanning(
    events,
    path_threshold=5,
    time_window=60
):
    alerts = []
    web_events_by_ip = defaultdict(list)

    for event in events:
        if not is_web_event(event):
            continue

        web_events_by_ip[event.get("ip")].append(event)

    for ip, ip_events in web_events_by_ip.items():
        ip_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(ip_events)):
            paths = set()
            first_time = ip_events[i]["timestamp"]
            last_time = first_time

            for j in range(i, len(ip_events)):
                current_event = ip_events[j]

                difference = (
                    current_event["timestamp"] - first_time
                ).total_seconds()

                if difference > time_window:
                    break

                path = current_event.get("path")

                if path:
                    paths.add(path)

                last_time = current_event["timestamp"]

            if len(paths) >= path_threshold:
                alerts.append({
                    "type": "Web Path Scanning",
                    "ip": ip,
                    "username": None,
                    "unique_paths": len(paths),
                    "paths": sorted(paths),
                    "time_window": f"{time_window} seconds",
                    "timestamp": first_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "first_seen": first_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "last_seen": last_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "severity": "HIGH",
                    "mitre_id": "T1595",
                    "mitre_name": "Active Scanning"
                })

                break

    return alerts


def detect_sensitive_file_access(events):
    alerts = []

    sensitive_patterns = [
        "/.env",
        "/.git",
        "/wp-config.php",
        "/config.php",
        "/phpinfo.php",
        "/etc/passwd",
        "/admin",
        "/administrator",
        "/server-status"
    ]

    for event in events:
        if not is_web_event(event):
            continue

        path = event.get("path", "").lower()

        matched_pattern = None

        for pattern in sensitive_patterns:
            if pattern.lower() in path:
                matched_pattern = pattern
                break

        if matched_pattern is None:
            continue

        alerts.append({
            "type": "Sensitive File Access",
            "ip": event.get("ip"),
            "username": None,
            "path": event.get("path"),
            "method": event.get("method"),
            "status_code": event.get("status_code"),
            "matched_pattern": matched_pattern,
            "timestamp": event["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "severity": "HIGH",
            "mitre_id": "T1595.002",
            "mitre_name": "Vulnerability Scanning"
        })

    return alerts


def detect_404_scanning(
    events,
    threshold=5,
    time_window=60
):
    alerts = []
    not_found_by_ip = defaultdict(list)

    for event in events:
        if not is_web_event(event):
            continue

        if event.get("status_code") != 404:
            continue

        not_found_by_ip[event.get("ip")].append(event)

    for ip, ip_events in not_found_by_ip.items():
        ip_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(ip_events)):
            matches = []
            first_time = ip_events[i]["timestamp"]

            for j in range(i, len(ip_events)):
                current_event = ip_events[j]

                difference = (
                    current_event["timestamp"] - first_time
                ).total_seconds()

                if difference > time_window:
                    break

                matches.append(current_event)

            if len(matches) >= threshold:
                alerts.append({
                    "type": "404 Scanning Activity",
                    "ip": ip,
                    "username": None,
                    "failed_requests": len(matches),
                    "paths": sorted({
                        event.get("path")
                        for event in matches
                        if event.get("path")
                    }),
                    "time_window": f"{time_window} seconds",
                    "timestamp": first_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "severity": "MEDIUM",
                    "mitre_id": "T1595",
                    "mitre_name": "Active Scanning"
                })

                break

    return alerts


def detect_request_flood(
    events,
    threshold=20,
    time_window=10
):
    alerts = []
    web_events_by_ip = defaultdict(list)

    for event in events:
        if not is_web_event(event):
            continue

        web_events_by_ip[event.get("ip")].append(event)

    for ip, ip_events in web_events_by_ip.items():
        ip_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(ip_events)):
            request_count = 1
            first_time = ip_events[i]["timestamp"]
            last_time = first_time

            for j in range(i + 1, len(ip_events)):
                current_event = ip_events[j]

                difference = (
                    current_event["timestamp"] - first_time
                ).total_seconds()

                if difference > time_window:
                    break

                request_count += 1
                last_time = current_event["timestamp"]

            if request_count >= threshold:
                alerts.append({
                    "type": "HTTP Request Flood",
                    "ip": ip,
                    "username": None,
                    "request_count": request_count,
                    "time_window": f"{time_window} seconds",
                    "timestamp": first_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "first_seen": first_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "last_seen": last_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "severity": "HIGH",
                    "mitre_id": "T1499",
                    "mitre_name": "Endpoint Denial of Service"
                })

                break

    return alerts


# =========================================================
# ALERT PROCESSING
# =========================================================

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
            current_alert["first_seen"] = (
                current_alert.get(
                    "first_seen",
                    timestamp_string
                )
            )
            current_alert["last_seen"] = (
                current_alert.get(
                    "last_seen",
                    timestamp_string
                )
            )

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


def calculate_risk_score(alert):
    score = 0

    severity_base = {
        "LOW": 20,
        "MEDIUM": 40,
        "HIGH": 65,
        "CRITICAL": 85
    }

    score += severity_base.get(
        alert.get("severity"),
        0
    )

    alert_type = alert.get("type", "")
    username = alert.get("username") or ""
    occurrences = alert.get(
        "occurrences",
        1
    )

    if alert_type == "Successful Login After Multiple Failures":
        score += 10

    elif alert_type == "Password Spraying Attack":
        score += 8

    elif alert_type == "Brute Force Attack":
        score += 6

    elif alert_type == "Root Login Attempt":
        score += 8

    elif alert_type == "Targeted Account Attack":
        score += 7

    elif alert_type == "Off-Hours Login":
        score += 4

    elif alert_type == "Web Path Scanning":
        score += 8

    elif alert_type == "Sensitive File Access":
        score += 10

    elif alert_type == "404 Scanning Activity":
        score += 5

    elif alert_type == "HTTP Request Flood":
        score += 9

    if username.lower() == "root":
        score += 8

    if occurrences > 1:
        score += min(
            occurrences * 2,
            10
        )

    if alert.get("trusted_ip"):
        score -= 15

    score = max(
        0,
        min(
            score,
            100
        )
    )

    if score >= 85:
        risk_level = "CRITICAL"

    elif score >= 65:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    alert["risk_score"] = score
    alert["risk_level"] = risk_level

    return alert


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

        calculate_risk_score(
            alert
        )

    return alerts


# =========================================================
# RUN ALL DETECTIONS
# =========================================================

def run_all_detections(
    events,
    config_path="config.json"
):
    alerts = []

    config = load_config(config_path)

    brute_force_config = config.get(
        "brute_force",
        {
            "enabled": True,
            "threshold": 3,
            "time_window": 60
        }
    )

    success_config = config.get(
        "success_after_failures",
        {
            "enabled": True,
            "threshold": 3,
            "time_window": 120
        }
    )

    spraying_config = config.get(
        "password_spraying",
        {
            "enabled": True,
            "user_threshold": 3,
            "time_window": 120
        }
    )

    targeted_config = config.get(
        "targeted_account",
        {
            "enabled": True,
            "ip_threshold": 3,
            "time_window": 300
        }
    )

    off_hours_config = config.get(
        "off_hours",
        {
            "enabled": True,
            "start_hour": 0,
            "end_hour": 5
        }
    )

    root_login_config = config.get(
        "root_login",
        {
            "enabled": True
        }
    )

    web_path_config = config.get(
        "web_path_scanning",
        {
            "enabled": True,
            "path_threshold": 5,
            "time_window": 60
        }
    )

    sensitive_file_config = config.get(
        "sensitive_file_access",
        {
            "enabled": True
        }
    )

    scanning_404_config = config.get(
        "404_scanning",
        {
            "enabled": True,
            "threshold": 5,
            "time_window": 60
        }
    )

    request_flood_config = config.get(
        "request_flood",
        {
            "enabled": True,
            "threshold": 20,
            "time_window": 10
        }
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

    if web_path_config["enabled"]:
        alerts.extend(
            detect_web_path_scanning(
                events,
                path_threshold=(
                    web_path_config[
                        "path_threshold"
                    ]
                ),
                time_window=(
                    web_path_config[
                        "time_window"
                    ]
                )
            )
        )

    if sensitive_file_config["enabled"]:
        alerts.extend(
            detect_sensitive_file_access(
                events
            )
        )

    if scanning_404_config["enabled"]:
        alerts.extend(
            detect_404_scanning(
                events,
                threshold=(
                    scanning_404_config[
                        "threshold"
                    ]
                ),
                time_window=(
                    scanning_404_config[
                        "time_window"
                    ]
                )
            )
        )

    if request_flood_config["enabled"]:
        alerts.extend(
            detect_request_flood(
                events,
                threshold=(
                    request_flood_config[
                        "threshold"
                    ]
                ),
                time_window=(
                    request_flood_config[
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