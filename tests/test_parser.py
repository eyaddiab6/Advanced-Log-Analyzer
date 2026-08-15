from parser import parse_log_line


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
    line = "This is not a valid SSH log"

    event = parse_log_line(line)

    assert event is None