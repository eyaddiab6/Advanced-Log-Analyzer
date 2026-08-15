from detector import calculate_risk_score


def test_high_risk_alert():
    alert = {
        "type":
            "Successful Login After Multiple Failures",
        "severity": "CRITICAL",
        "username": "admin",
        "occurrences": 1,
        "trusted_ip": False
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 95
    assert result["risk_level"] == "CRITICAL"


def test_root_account_increases_risk():
    alert = {
        "type": "Root Login Attempt",
        "severity": "HIGH",
        "username": "root",
        "occurrences": 1,
        "trusted_ip": False
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 81
    assert result["risk_level"] == "HIGH"


def test_trusted_ip_reduces_risk():
    alert = {
        "type": "Brute Force Attack",
        "severity": "MEDIUM",
        "username": "admin",
        "occurrences": 1,
        "trusted_ip": True
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 31
    assert result["risk_level"] == "LOW"


def test_risk_score_never_exceeds_100():
    alert = {
        "type": "Root Login Attempt",
        "severity": "CRITICAL",
        "username": "root",
        "occurrences": 20,
        "trusted_ip": False
    }

    result = calculate_risk_score(
        alert
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"