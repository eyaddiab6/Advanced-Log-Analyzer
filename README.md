# Advanced Log Analyzer

Advanced Log Analyzer is a Python-based cybersecurity project that analyzes Linux SSH authentication logs and web server access logs, detects suspicious activity, maps detections to MITRE ATT&CK techniques, calculates contextual risk scores, and displays the results in an interactive Flask dashboard.

The project is designed as a lightweight SIEM-style security monitoring tool for learning log analysis, detection engineering, alert aggregation, risk scoring, multi-source parsing, automated testing, investigation workflows, and security visualization.

---

## Current Version

**Version 2.0**

Version 2.0 expands the project from an SSH-focused analyzer into a multi-source security monitoring platform.

The current release supports:

- Linux SSH authentication logs
- Apache access logs
- Nginx access logs
- Automatic SSH vs web log detection
- SSH-focused detections
- Web-focused detections
- MITRE ATT&CK mapping
- Alert aggregation
- Trusted IP handling
- Contextual risk scoring
- Highest-risk alert identification
- Multi-source security timeline
- Interactive investigation
- Downloadable JSON and CSV reports
- 25 automated tests using pytest

---

## Features

### Log Parsing

- Linux SSH authentication log parsing
- Apache access log parsing
- Nginx access log parsing
- Automatic SSH vs web log detection
- Apache/Nginx source identification using filenames
- Chronological event sorting

### SSH Detection Rules

- Brute-force attack detection
- Successful login after multiple failures detection
- Root login attempt detection
- Off-hours login detection
- Password spraying detection
- Targeted account attack detection

### Web Detection Rules

- Web path scanning detection
- Sensitive file access detection
- HTTP 404 scanning detection
- HTTP request flood detection

### Alert Processing

- Config-driven detection rules
- Trusted IP severity reduction
- Alert aggregation with configurable time windows
- Severity classification
- Contextual risk score from `0-100`
- Risk level classification
- Highest-risk alert detection
- Unique alert and occurrence tracking
- MITRE ATT&CK mapping

### Dashboard and Reporting

- Interactive Flask SOC-style dashboard
- Multi-source security timeline
- SSH and web event counters
- Alerts by severity chart
- Login activity chart
- HTTP status activity chart
- HTTP 2xx / 3xx / 4xx / 5xx statistics
- Top attacking IP analysis
- Most targeted user analysis
- Top requested web paths
- Log source statistics
- Alert investigation panel
- Alert search
- Severity filtering
- JSON security report export
- CSV alert export
- Downloadable reports from the dashboard
- Upload and analyze `.log` or `.txt` files

### Testing

- 25 automated tests using pytest
- SSH parser tests
- Apache parser tests
- Nginx parser tests
- SSH detection tests
- Web detection tests
- Aggregation tests
- Risk scoring tests
- Cross-source isolation tests

---

## Detection Rules

### SSH Detections

### 1. Brute Force Attack

Detects multiple failed authentication attempts against the same username from the same IP address within a configured time window.

**MITRE ATT&CK**

- Technique: T1110.001
- Name: Password Guessing

---

### 2. Successful Login After Multiple Failures

Detects a successful login that occurs after several failed authentication attempts from the same source IP against the same account.

This can indicate that an attacker successfully guessed or obtained valid credentials.

**MITRE ATT&CK**

- Technique: T1078
- Name: Valid Accounts

---

### 3. Root Login Attempt

Detects authentication attempts targeting the privileged `root` account.

Successful root authentication attempts receive a higher severity level.

**MITRE ATT&CK**

- Technique: T1078
- Name: Valid Accounts

---

### 4. Off-Hours Login

Detects successful authentication events during configured off-hours.

The default configuration monitors logins between:

```text
00:00 - 05:00
```

**MITRE ATT&CK**

- Technique: T1078
- Name: Valid Accounts

---

### 5. Password Spraying Attack

Detects one source IP attempting authentication against several different usernames within a short time period.

**MITRE ATT&CK**

- Technique: T1110.003
- Name: Password Spraying

---

### 6. Targeted Account Attack

Detects one username being targeted by failed authentication attempts from several different source IP addresses.

**MITRE ATT&CK**

- Technique: T1110
- Name: Brute Force

---

## Web Detection Rules

### 7. Web Path Scanning

Detects a source IP requesting many different web paths within a short time window.

This can indicate automated reconnaissance, directory discovery, or application mapping.

**MITRE ATT&CK**

- Technique: T1595
- Name: Active Scanning

---

### 8. Sensitive File Access

Detects requests targeting sensitive or commonly exposed paths such as:

```text
/.env
/.git
/wp-config.php
/config.php
/phpinfo.php
/etc/passwd
/admin
/administrator
/server-status
```

**MITRE ATT&CK**

- Technique: T1595.002
- Name: Vulnerability Scanning

---

### 9. 404 Scanning Activity

Detects a source IP generating multiple HTTP `404 Not Found` responses within a short time window.

A large number of failed path requests can indicate automated path discovery or reconnaissance.

**MITRE ATT&CK**

- Technique: T1595
- Name: Active Scanning

---

### 10. HTTP Request Flood

Detects a high number of HTTP requests from the same source IP within a short time window.

This can indicate abusive automation or denial-of-service style activity.

**MITRE ATT&CK**

- Technique: T1499
- Name: Endpoint Denial of Service

---

## Multi-Source Parsing

Version 2.0 introduces multi-source parsing.

The parser can identify:

```text
SSH authentication events
HTTP access-log events
```

For common Apache and Nginx access-log formats, the log line itself may be structurally identical.

The project therefore identifies web events from their format and uses the filename when available to label the source as:

```text
apache
nginx
web
```

Example Apache/Nginx access log:

```text
8.8.8.8 - - [15/Aug/2026:20:00:01 +0300] "GET /admin HTTP/1.1" 404 512
```

Parsed fields include:

- Timestamp
- Source type
- Source IP
- HTTP method
- Request path
- HTTP protocol
- Status code
- Response size

---

## Risk Scoring

Each alert receives:

```text
risk_score: 0-100
risk_level: LOW / MEDIUM / HIGH / CRITICAL
```

The risk engine considers factors such as:

- Alert severity
- Detection type
- Number of occurrences
- Privileged usernames such as `root`
- Successful authentication after repeated failures
- Trusted IP status
- Web attack category

Example:

```text
Type: Sensitive File Access
Severity: HIGH
Risk Score: 85/100
Risk Level: CRITICAL
```

Severity and risk level are intentionally separate concepts.

For example, an alert may have:

```text
Severity: HIGH
Risk Level: CRITICAL
```

because the contextual risk score includes additional factors beyond the base severity.

---

## Highest Risk Detection

The dashboard automatically identifies the alert with the highest calculated risk score.

Example:

```text
HIGHEST RISK DETECTION

Sensitive File Access
ALERT-002 • 8.8.8.8 • N/A

Risk Score
85/100
CRITICAL
```

This helps analysts immediately identify the alert that should receive the highest investigation priority.

---

## Alert Aggregation

Repeated alerts with the same:

- Alert type
- Source IP
- Username

can be grouped into a single alert when they occur close together.

Example:

```text
13:01:00 Root Login Attempt
13:01:20 Root Login Attempt
```

can become:

```text
Occurrences: 2
First Seen: 2026-08-15 13:01:00
Last Seen: 2026-08-15 13:01:20
```

Aggregation is also used for web detections.

For example, multiple sensitive-path requests can be represented as one aggregated alert with multiple occurrences.

---

## Trusted IP Handling

Trusted IP addresses can be configured inside `config.json`.

Instead of suppressing detections completely, the project reduces the severity of alerts generated by trusted IP addresses.

Example:

```text
CRITICAL -> HIGH
HIGH     -> MEDIUM
MEDIUM   -> LOW
LOW      -> LOW
```

The alert keeps its original severity for investigation.

Trusted IP status also contributes to the final risk score.

---

## Security Timeline

The dashboard includes a chronological security timeline for both SSH and web events.

### SSH Timeline Example

```text
20:00:01  SSH FAILED   admin   8.8.8.8
20:00:10  SSH FAILED   admin   8.8.8.8
20:01:00  SSH SUCCESS  admin   8.8.8.8
```

### Web Timeline Example

```text
20:00:00  GET 200  /             8.8.8.8  APACHE
20:00:01  GET 404  /admin        8.8.8.8  APACHE
20:00:02  GET 404  /.env         8.8.8.8  APACHE
20:00:03  GET 404  /.git/config  8.8.8.8  APACHE
```

The timeline helps analysts understand how suspicious activity developed over time.

---

## Dashboard

The Flask dashboard provides a SOC-style interface that adapts to the uploaded log source.

### Common Dashboard Information

- Total parsed events
- SSH event count
- Web event count
- Unique alerts
- Total alert occurrences
- Critical severity count
- High severity count
- Medium severity count
- Highest-risk detection
- Alerts by severity chart
- Top attacking IPs
- MITRE ATT&CK summary
- Alert investigation
- Downloadable reports

### SSH Mode

When analyzing SSH logs, the dashboard shows:

- Login activity chart
- Successful logins
- Failed logins
- Most targeted users
- SSH security timeline

### Web Mode

When analyzing Apache or Nginx logs, the dashboard shows:

- HTTP status activity chart
- HTTP 2xx responses
- HTTP 3xx responses
- HTTP 4xx responses
- HTTP 5xx responses
- Top requested paths
- Primary log source
- Web security timeline

---

## Alert Investigation

Clicking an alert in the Security Alerts table opens a detailed investigation section.

The investigation panel supports both SSH and web alerts.

### Common Fields

- Alert ID
- Alert type
- Severity
- Risk score
- Risk level
- Source IP
- MITRE technique
- Occurrences
- Time window
- First seen
- Last seen
- Detection explanation

### SSH-Specific Fields

- Username
- Login status
- Failed attempts
- Previous failures

### Web-Specific Fields

- HTTP method
- Request path
- HTTP status code
- Failed request count
- Request count
- Matched sensitive pattern

---

## Alert Search and Filtering

The Security Alerts table supports searching by:

- Alert ID
- IP address
- Username
- Alert type
- MITRE technique
- Risk score
- Risk level
- HTTP method
- Request path
- HTTP status code
- Sensitive matched pattern

The dashboard also supports:

- Severity filtering
- Clear filters
- Dynamic visible-alert count

---

## Log Upload

The dashboard supports uploading:

```text
.log
.txt
```

files directly from the browser.

After selecting a file and clicking:

```text
Analyze Logs
```

the application performs:

```text
Upload
   ↓
Detect Log Format
   ↓
Parse
   ↓
Classify Source
   ↓
Run SSH / Web Detections
   ↓
Trusted IP Adjustment
   ↓
Aggregate Alerts
   ↓
Risk Scoring
   ↓
MITRE Mapping
   ↓
Generate Summary
   ↓
Export Reports
   ↓
Display Dashboard
```

---

## Example Log Formats

### Linux SSH

```text
Aug 15 12:10:31 server sshd[1234]: Failed password for admin from 192.168.1.20 port 55231 ssh2
Aug 15 12:10:35 server sshd[1235]: Failed password for admin from 192.168.1.20 port 55232 ssh2
Aug 15 12:10:50 server sshd[1238]: Accepted password for admin from 192.168.1.20 port 55235 ssh2
```

### Apache / Nginx

```text
8.8.8.8 - - [15/Aug/2026:20:00:00 +0300] "GET / HTTP/1.1" 200 1200
8.8.8.8 - - [15/Aug/2026:20:00:01 +0300] "GET /admin HTTP/1.1" 404 512
8.8.8.8 - - [15/Aug/2026:20:00:02 +0300] "GET /.env HTTP/1.1" 404 300
```

Sample logs are available in the `logs/` directory.

---

## Project Structure

```text
Advanced-Log-Analyzer/
│
├── logs/
│   ├── auth.log
│   ├── test_attack.log
│   └── apache_attack.log
│
├── reports/
│
├── static/
│   └── style.css
│
├── templates/
│   └── dashboard.html
│
├── tests/
│   ├── conftest.py
│   ├── test_aggregation.py
│   ├── test_detector.py
│   ├── test_parser.py
│   ├── test_risk_score.py
│   └── test_web_detector.py
│
├── app.py
├── config.json
├── detector.py
├── main.py
├── parser.py
├── reporter.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Configuration

Detection rules are controlled through `config.json`.

Example:

```json
{
    "brute_force": {
        "enabled": true,
        "threshold": 3,
        "time_window": 60
    },

    "success_after_failures": {
        "enabled": true,
        "threshold": 3,
        "time_window": 120
    },

    "password_spraying": {
        "enabled": true,
        "user_threshold": 3,
        "time_window": 120
    },

    "targeted_account": {
        "enabled": true,
        "ip_threshold": 3,
        "time_window": 300
    },

    "off_hours": {
        "enabled": true,
        "start_hour": 0,
        "end_hour": 5
    },

    "root_login": {
        "enabled": true
    },

    "web_path_scanning": {
        "enabled": true,
        "path_threshold": 5,
        "time_window": 60
    },

    "sensitive_file_access": {
        "enabled": true
    },

    "404_scanning": {
        "enabled": true,
        "threshold": 5,
        "time_window": 60
    },

    "request_flood": {
        "enabled": true,
        "threshold": 20,
        "time_window": 10
    },

    "trusted_ips": [
        "192.168.1.20"
    ],

    "aggregation": {
        "time_window": 600
    }
}
```

Rules can be enabled or disabled without changing the detection code.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/eyaddiab6/Advanced-Log-Analyzer.git
```

Enter the project directory:

```bash
cd Advanced-Log-Analyzer
```

Install the project dependencies:

```bash
pip install -r requirements.txt
```

The current requirements include:

```text
Flask==3.1.2
pytest==9.1.1
```

---

## Running the Command-Line Analyzer

Run:

```bash
python main.py
```

The command-line analyzer performs the configured detection workflow and generates security reports.

---

## Running the Dashboard

Run:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

in your browser.

Upload an SSH, Apache, or Nginx log file using the dashboard.

---

## Automated Tests

Version 2.0 includes **25 automated tests** using `pytest`.

The test suite covers:

### Parsing

- Failed SSH log parsing
- Successful SSH log parsing
- Invalid log handling
- Web log detection
- Apache access-log parsing
- Nginx access-log parsing
- Web server identification from filenames

### SSH Detection

- Brute force detection
- Successful login after multiple failures
- Root login detection
- Password spraying detection

### Web Detection

- Web path scanning
- Sensitive file access
- Normal-path false-positive check
- 404 scanning
- HTTP request flood
- Web events excluded from SSH brute-force detection

### Alert Processing

- Alert aggregation
- Separation of alerts from different IPs

### Risk Scoring

- High-risk alert scoring
- Root account risk increase
- Trusted IP risk reduction
- Maximum risk-score cap
- Sensitive-file web alert risk
- Web path scanning risk

Run:

```bash
pytest -v
```

Expected result:

```text
25 passed
```

---

## Generated Reports

The analyzer generates:

```text
reports/security_report.json
reports/alerts.csv
```

Report data can include:

- Alert ID
- Alert type
- Severity
- Severity score
- Risk score
- Risk level
- Trusted IP status
- Original severity
- Source IP
- Username
- MITRE ATT&CK mapping
- HTTP method
- HTTP path
- HTTP status code
- Sensitive matched pattern
- Failed request count
- Request count
- Unique paths
- Occurrences
- First seen
- Last seen

The JSON and CSV reports can also be downloaded directly from the Flask dashboard.

Generated report files are excluded from Git tracking through `.gitignore`.

---

## Technologies Used

- Python
- Flask
- pytest
- HTML
- CSS
- JavaScript
- Chart.js
- Regular Expressions
- JSON
- CSV
- MITRE ATT&CK
- Git
- GitHub

---

## Version History

### v2.0

- Added Apache access-log support
- Added Nginx access-log support
- Added automatic SSH vs web log detection
- Added Apache/Nginx source identification
- Added web path scanning detection
- Added sensitive file access detection
- Added HTTP 404 scanning detection
- Added HTTP request flood detection
- Added web-focused MITRE ATT&CK mappings
- Extended risk scoring to web alerts
- Added HTTP statistics
- Added HTTP status activity visualization
- Added top requested path analysis
- Added multi-source security timeline
- Extended alert investigation with HTTP fields
- Added multi-source dashboard behavior
- Added `requirements.txt`
- Expanded automated test suite from 13 to 25 tests
- Preserved SSH functionality from earlier releases

### v1.1

- Added contextual risk scoring
- Added risk levels
- Added highest-risk detection card
- Added security event timeline
- Added downloadable JSON reports
- Added downloadable CSV reports
- Added 13 automated pytest tests
- Improved dashboard investigation workflow
- Extended CSV and JSON alert metadata

### v1.0

- Added Linux SSH log parsing
- Added six SSH security detection rules
- Added MITRE ATT&CK mapping
- Added config-driven detection
- Added trusted IP severity reduction
- Added alert aggregation
- Added JSON and CSV report generation
- Added Flask SOC-style dashboard
- Added log upload
- Added alert investigation
- Added alert search and severity filtering

---

## Planned Improvements

Future development may include:

- IOC extraction
- More advanced alert correlation
- Attack-chain detection
- Additional risk-scoring factors
- Threat intelligence enrichment
- More detection rules
- Additional dashboard filters
- Detection rules for additional HTTP attack patterns
- Additional log sources
- Larger automated test suite
- More robust log-format normalization

The long-term goal is to continue expanding the project into a multi-source lightweight SIEM-style log analysis platform.

---

## Disclaimer

This project was created for cybersecurity learning, defensive security research, and portfolio purposes.

It is not intended to replace a production SIEM or enterprise security monitoring platform.

---

## Author

**Eyad Diab**

Cybersecurity Student / Developer

GitHub:

```text
https://github.com/eyaddiab6
```
