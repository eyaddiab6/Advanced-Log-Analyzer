import re
from datetime import datetime
from pathlib import Path


SSH_PATTERN = re.compile(
    r"(?P<month>\w{3}) "
    r"(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"(?P<status>Failed|Accepted) password for "
    r"(?P<username>\w+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


WEB_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'\S+ '
    r'\S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) '
    r'(?P<path>\S+) '
    r'(?P<protocol>[^"]+)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<size>\S+)'
)


def detect_log_source(line):
    if SSH_PATTERN.search(line):
        return "ssh"

    if WEB_PATTERN.search(line):
        return "web"

    return "unknown"


def parse_ssh_line(line, year=2026):
    match = SSH_PATTERN.search(line)

    if not match:
        return None

    data = match.groupdict()

    timestamp_text = (
        f"{year} "
        f"{data['month']} "
        f"{data['day']} "
        f"{data['time']}"
    )

    timestamp = datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S"
    )

    return {
        "timestamp": timestamp,
        "source_type": "ssh",
        "event_type": "ssh_login",
        "username": data["username"],
        "ip": data["ip"],
        "status": (
            "failed"
            if data["status"] == "Failed"
            else "success"
        )
    }


def parse_web_line(line, server_type="web"):
    match = WEB_PATTERN.search(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None

    size = data["size"]

    if size == "-":
        size = 0
    else:
        try:
            size = int(size)
        except ValueError:
            size = 0

    return {
        "timestamp": timestamp,
        "source_type": server_type,
        "event_type": "http_request",
        "ip": data["ip"],
        "method": data["method"],
        "path": data["path"],
        "protocol": data["protocol"],
        "status_code": int(
            data["status_code"]
        ),
        "response_size": size
    }


def parse_log_line(
    line,
    year=2026,
    source_hint=None
):
    source = detect_log_source(line)

    if source == "ssh":
        return parse_ssh_line(
            line,
            year
        )

    if source == "web":
        return parse_web_line(
            line,
            source_hint or "web"
        )

    return None


def detect_server_type_from_filename(
    file_path
):
    filename = Path(
        file_path
    ).name.lower()

    if "nginx" in filename:
        return "nginx"

    if "apache" in filename:
        return "apache"

    return "web"


def parse_log_file(
    file_path,
    year=2026
):
    events = []

    web_server_type = (
        detect_server_type_from_filename(
            file_path
        )
    )

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line in file:

            source = detect_log_source(
                line
            )

            if source == "ssh":
                event = parse_ssh_line(
                    line,
                    year
                )

            elif source == "web":
                event = parse_web_line(
                    line,
                    web_server_type
                )

            else:
                event = None

            if event:
                events.append(
                    event
                )

    events.sort(
        key=lambda event:
        event["timestamp"]
    )

    return events