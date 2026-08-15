from datetime import datetime

from detector import (
    detect_web_path_scanning,
    detect_sensitive_file_access,
    detect_404_scanning,
    detect_request_flood,
    detect_brute_force,
    calculate_risk_score
)


def make_web_event(
    timestamp,
    ip,
    method,
    path,
    status_code,
    source_type="apache"
):
    return {
        "timestamp": datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        ),
        "source_type": source_type,
        "event_type": "http_request",
        "ip": ip,
        "method": method,
        "path": path,
        "protocol": "HTTP/1.1",
        "status_code": status_code,
        "response_size": 500
    }


def test_web_path_scanning_detection():
    events = [
        make_web_event(
            "2026-08-15 20:00:00",
            "8.8.8.8",
            "GET",
            "/",
            200
        ),
        make_web_event(
            "2026-08-15 20:00:05",
            "8.8.8.8",
            "GET",
            "/admin",
            404
        ),
        make_web_event(
            "2026-08-15 20:00:10",
            "8.8.8.8",
            "GET",
            "/login",
            200
        ),
        make_web_event(
            "2026-08-15 20:00:15",
            "8.8.8.8",
            "GET",
            "/api",
            200
        ),
        make_web_event(
            "2026-08-15 20:00:20",
            "8.8.8.8",
            "GET",
            "/dashboard",
            200
        )
    ]

    alerts = detect_web_path_scanning(
        events,
        path_threshold=5,
        time_window=60
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "Web Path Scanning"
    assert alert["ip"] == "8.8.8.8"
    assert alert["unique_paths"] == 5
    assert alert["severity"] == "HIGH"
    assert alert["mitre_id"] == "T1595"


def test_sensitive_file_access_detection():
    events = [
        make_web_event(
            "2026-08-15 20:00:00",
            "8.8.8.8",
            "GET",
            "/.env",
            404
        )
    ]

    alerts = detect_sensitive_file_access(
        events
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "Sensitive File Access"
    assert alert["path"] == "/.env"
    assert alert["matched_pattern"] == "/.env"
    assert alert["method"] == "GET"
    assert alert["status_code"] == 404
    assert alert["severity"] == "HIGH"
    assert alert["mitre_id"] == "T1595.002"


def test_normal_web_path_does_not_trigger_sensitive_file_alert():
    events = [
        make_web_event(
            "2026-08-15 20:00:00",
            "8.8.8.8",
            "GET",
            "/products",
            200
        )
    ]

    alerts = detect_sensitive_file_access(
        events
    )

    assert len(alerts) == 0


def test_404_scanning_detection():
    events = [
        make_web_event(
            "2026-08-15 20:00:00",
            "10.0.0.5",
            "GET",
            "/one",
            404
        ),
        make_web_event(
            "2026-08-15 20:00:05",
            "10.0.0.5",
            "GET",
            "/two",
            404
        ),
        make_web_event(
            "2026-08-15 20:00:10",
            "10.0.0.5",
            "GET",
            "/three",
            404
        ),
        make_web_event(
            "2026-08-15 20:00:15",
            "10.0.0.5",
            "GET",
            "/four",
            404
        ),
        make_web_event(
            "2026-08-15 20:00:20",
            "10.0.0.5",
            "GET",
            "/five",
            404
        )
    ]

    alerts = detect_404_scanning(
        events,
        threshold=5,
        time_window=60
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "404 Scanning Activity"
    assert alert["ip"] == "10.0.0.5"
    assert alert["failed_requests"] == 5
    assert alert["severity"] == "MEDIUM"
    assert alert["mitre_id"] == "T1595"


def test_request_flood_detection():
    events = []

    for second in range(20):
        events.append(
            make_web_event(
                f"2026-08-15 20:00:{second:02d}",
                "172.16.0.50",
                "GET",
                "/api",
                200
            )
        )

    alerts = detect_request_flood(
        events,
        threshold=10,
        time_window=10
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "HTTP Request Flood"
    assert alert["ip"] == "172.16.0.50"
    assert alert["request_count"] >= 10
    assert alert["severity"] == "HIGH"
    assert alert["mitre_id"] == "T1499"


def test_web_event_does_not_trigger_ssh_brute_force():
    events = [
        make_web_event(
            "2026-08-15 20:00:00",
            "8.8.8.8",
            "POST",
            "/login",
            401
        ),
        make_web_event(
            "2026-08-15 20:00:05",
            "8.8.8.8",
            "POST",
            "/login",
            401
        ),
        make_web_event(
            "2026-08-15 20:00:10",
            "8.8.8.8",
            "POST",
            "/login",
            401
        )
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        time_window=60
    )

    assert len(alerts) == 0


def test_sensitive_file_access_risk_score():
    alert = {
        "type": "Sensitive File Access",
        "severity": "HIGH",
        "username": None,
        "occurrences": 1,
        "trusted_ip": False
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 75
    assert result["risk_level"] == "HIGH"


def test_web_path_scanning_risk_score():
    alert = {
        "type": "Web Path Scanning",
        "severity": "HIGH",
        "username": None,
        "occurrences": 1,
        "trusted_ip": False
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 73
    assert result["risk_level"] == "HIGH"