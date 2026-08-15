import re
from datetime import datetime


def parse_log_line(line, year=2026):
    pattern = (
        r"(?P<month>\w{3}) "
        r"(?P<day>\d{1,2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}).*"
        r"(?P<status>Failed|Accepted) password for "
        r"(?P<username>\w+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern, line)

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
        "username": data["username"],
        "ip": data["ip"],
        "status": (
            "failed"
            if data["status"] == "Failed"
            else "success"
        ),
        "event_type": "ssh_login"
    }


def parse_log_file(file_path, year=2026):
    events = []

    with open(file_path, "r") as file:
        for line in file:
            event = parse_log_line(line, year)

            if event:
                events.append(event)

    events.sort(
        key=lambda event: event["timestamp"]
    )

    return events