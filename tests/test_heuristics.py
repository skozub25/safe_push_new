from scanner.core import scan_line, Finding


def make_findings(line: str) -> list[Finding]:
    return scan_line("example.py", 10, line)


def test_high_entropy_in_sensitive_context_triggers():
    # len >= 24 AND high entropy AND sensitive keyword present.
    token = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    line = f'db_password = "{token}"'
    findings = make_findings(line)

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "example.py"
    assert f.line_no == 10
    # Classic reason string preserved for HIGH severity
    assert "High-entropy value in sensitive context" in f.reason
    assert f.severity == "HIGH"


def test_high_entropy_without_sensitive_context_is_ignored_by_high_rule_but_flagged_medium():
    token = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    line = f'session_id = "{token}"'
    findings = make_findings(line)

    # With new rules we *do* flag this, but at MEDIUM severity.
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MEDIUM"
    assert "Suspicious high-entropy value" in f.reason


def test_short_token_in_sensitive_context_now_flagged_medium():
    line = 'db_password = "short123"'
    findings = make_findings(line)

    # New behavior: context + len >= 8 => MEDIUM
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MEDIUM"
    assert "Suspicious value in sensitive context" in f.reason


def test_low_entropy_long_token_in_sensitive_context_now_flagged_medium():
    token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # long but low entropy
    line = f'api_key = "{token}"'
    findings = make_findings(line)

    # New behavior: context alone is enough for MEDIUM (regardless of entropy)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MEDIUM"
    assert "Suspicious value in sensitive context" in f.reason


def test_multiple_high_entropy_tokens_in_one_line_all_flagged():
    token1 = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    token2 = "Q1w2E3r4T5y6U7i8O9p0AaBbCc"
    line = f'app_secret = "{token1}"  # another "{token2}"'
    findings = make_findings(line)

    # Both should be caught as HIGH with the classic reason string
    assert len(findings) == 2
    for f in findings:
        assert f.severity == "HIGH"
        assert "High-entropy value in sensitive context" in f.reason