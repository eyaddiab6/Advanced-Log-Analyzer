from parser import (
    parse_log_line,
    detect_log_source,
    detect_server_type_from_filename
)


def test_parse_failed_login():
    line = (
        "Aug 15 12:10:31 server sshd[1234]: "
        "Failed password for admin from "
        "192.168.1.20 port 55231 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["username"] == "admin"
    assert event["ip"] == "192.168.1.20"
    assert event["status"] == "failed"
    assert event["event_type"] == "ssh_login"


def test_parse_successful_login():
    line = (
        "Aug 15 12:10:50 server sshd[1238]: "
        "Accepted password for eyad from "
        "192.168.1.10 port 55235 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["username"] == "eyad"
    assert event["ip"] == "192.168.1.10"
    assert event["status"] == "success"


def test_invalid_log_line():
    line = "This is not a valid SSH or web log"

    event = parse_log_line(line)

    assert event is None


def test_detect_web_log():
    line = (
        '192.168.1.50 - - '
        '[15/Aug/2026:20:15:10 +0300] '
        '"GET /admin HTTP/1.1" 404 512'
    )

    source = detect_log_source(line)

    assert source == "web"


def test_parse_apache_log():
    line = (
        '192.168.1.50 - - '
        '[15/Aug/2026:20:15:10 +0300] '
        '"GET /admin HTTP/1.1" 404 512'
    )

    event = parse_log_line(
        line,
        source_hint="apache"
    )

    assert event is not None

    assert event["source_type"] == "apache"
    assert event["event_type"] == "http_request"

    assert event["ip"] == "192.168.1.50"
    assert event["method"] == "GET"
    assert event["path"] == "/admin"

    assert event["status_code"] == 404
    assert event["response_size"] == 512


def test_parse_nginx_log():
    line = (
        '8.8.8.8 - - '
        '[15/Aug/2026:21:00:00 +0300] '
        '"POST /login HTTP/1.1" 200 1024'
    )

    event = parse_log_line(
        line,
        source_hint="nginx"
    )

    assert event is not None

    assert event["source_type"] == "nginx"
    assert event["event_type"] == "http_request"

    assert event["ip"] == "8.8.8.8"
    assert event["method"] == "POST"
    assert event["path"] == "/login"

    assert event["status_code"] == 200
    assert event["response_size"] == 1024


def test_detect_server_from_filename():
    assert (
        detect_server_type_from_filename(
            "logs/apache_access.log"
        )
        == "apache"
    )

    assert (
        detect_server_type_from_filename(
            "logs/nginx_access.log"
        )
        == "nginx"
    )