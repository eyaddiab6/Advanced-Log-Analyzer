from datetime import datetime

from detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_root_login_attempts,
    detect_password_spraying
)


def make_event(
    timestamp,
    username,
    ip,
    status
):
    return {
        "timestamp": datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        ),
        "username": username,
        "ip": ip,
        "status": status,
        "event_type": "ssh_login"
    }


def test_brute_force_detection():
    events = [
        make_event(
            "2026-08-15 12:00:00",
            "admin",
            "10.0.0.1",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:10",
            "admin",
            "10.0.0.1",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:20",
            "admin",
            "10.0.0.1",
            "failed"
        )
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        time_window=60
    )

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Brute Force Attack"
    assert alerts[0]["ip"] == "10.0.0.1"
    assert alerts[0]["username"] == "admin"


def test_success_after_failures():
    events = [
        make_event(
            "2026-08-15 12:00:00",
            "admin",
            "10.0.0.1",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:10",
            "admin",
            "10.0.0.1",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:20",
            "admin",
            "10.0.0.1",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:30",
            "admin",
            "10.0.0.1",
            "success"
        )
    ]

    alerts = detect_success_after_failures(
        events,
        threshold=3,
        time_window=120
    )

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "Successful Login After Multiple Failures"
    )

    assert alerts[0]["previous_failures"] == 3


def test_root_login_detection():
    events = [
        make_event(
            "2026-08-15 12:00:00",
            "root",
            "10.0.0.5",
            "failed"
        )
    ]

    alerts = detect_root_login_attempts(
        events
    )

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Root Login Attempt"
    assert alerts[0]["username"] == "root"


def test_password_spraying_detection():
    events = [
        make_event(
            "2026-08-15 12:00:00",
            "admin",
            "10.0.0.9",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:10",
            "guest",
            "10.0.0.9",
            "failed"
        ),
        make_event(
            "2026-08-15 12:00:20",
            "test",
            "10.0.0.9",
            "failed"
        )
    ]

    alerts = detect_password_spraying(
        events,
        user_threshold=3,
        time_window=120
    )

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "Password Spraying Attack"
    )

    assert alerts[0]["unique_users"] == 3