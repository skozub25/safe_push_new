from scanner.core import scan_line

def make_findings(line: str):
    return scan_line("example.py", 10, line)

def test_benign_line_has_no_findings():
    findings = make_findings('message = "hello world, nothing secret here"')
    assert findings == []

def test_high_entropy_in_sensitive_context_triggers():
    # Token chosen to satisfy current heuristic:
    # len >= 24 AND entropy >= 4.0 AND sensitive keyword present.
    token = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    line = f'db_password = "{token}"'
    findings = make_findings(line)

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "example.py"
    assert f.line_no == 10
    assert "High-entropy value in sensitive context" in f.reason

def test_high_entropy_without_sensitive_context_is_ignored():
    token = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    line = f'session_id = "{token}"'
    findings = make_findings(line)
    assert findings == []

def test_short_token_in_sensitive_context_not_flagged():
    line = 'db_password = "short123"'
    findings = make_findings(line)
    assert findings == []

def test_low_entropy_long_token_in_sensitive_context_not_flagged():
    token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # long but zero entropy
    line = f'api_key = "{token}"'
    findings = make_findings(line)
    assert findings == []  # requires entropy check to be in play

def test_multiple_high_entropy_tokens_in_one_line_all_flagged():
    token1 = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"
    token2 = "Q1w2E3r4T5y6U7i8O9p0AaBbCc"
    line = f'app_secret = "{token1}"  # another "{token2}"'
    findings = make_findings(line)

    # Both should be caught by the heuristic under current rules
    assert len(findings) == 2
    for f in findings:
        assert "High-entropy value in sensitive context" in f.reason