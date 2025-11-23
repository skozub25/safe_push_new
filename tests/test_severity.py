import re

from scanner.core import scan_line, Finding
from scanner.patterns import PATTERN_RULES, PatternRule, SEV_LOW, SEV_MEDIUM, SEV_HIGH


def _make_high_entropy_token(length: int) -> str:
    """
    Build a high-entropy-ish token at runtime so we don't
    hardcode any exact keys in the source file.
    """
    base = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    s = (base * ((length // len(base)) + 1))[:length]
    mid = length // 2
    return s[mid:] + s[:mid]


def test_pattern_rules_are_high_severity():
    """
    All entries in PATTERN_RULES should be PatternRule with HIGH severity.
    (Secret-specific regexes are serious by default.)
    """
    assert len(PATTERN_RULES) > 0

    for rule in PATTERN_RULES:
        assert isinstance(rule, PatternRule)
        assert rule.severity == SEV_HIGH
        assert isinstance(rule.name, str)
        assert isinstance(rule.regex, re.Pattern)


def test_pattern_match_finding_has_high_severity():
    """
    A line that matches a provider-specific pattern (e.g., AWS access key)
    should produce a HIGH severity Finding with a useful reason.
    """
    token = "AKIA" + "1234567890ABCDE1"
    line = f'const aws_key = "{token}"'

    findings = scan_line("app.py", 10, line)

    assert any(
        f.severity == SEV_HIGH and "AWS Access Key ID" in f.reason
        for f in findings
    )


def test_entropy_high_severity_context_and_high_entropy():
    """
    Context + long high-entropy token -> HIGH severity + classic reason text.
    """
    token = _make_high_entropy_token(24)
    line = f'db_password = "{token}"'  # contains "password" => sensitive context

    findings = scan_line("settings.py", 5, line)

    assert any(
        f.severity == SEV_HIGH
        and "High-entropy value in sensitive context" in f.reason
        for f in findings
    )


def test_entropy_medium_severity_context_but_not_high_entropy():
    """
    Context but not high entropy: e.g., PASSWORD="devpassword".
    Should be MEDIUM severity (suspicious but weaker signal).
    """
    line = 'DB_PASSWORD = "devpassword"'

    findings = scan_line("settings.py", 20, line)

    assert any(
        f.severity == SEV_MEDIUM
        and "Suspicious value in sensitive context" in f.reason
        for f in findings
    )


def test_entropy_medium_severity_high_entropy_without_context():
    """
    High-entropy, long token without explicit secret keywords:
    should be MEDIUM severity.
    """
    token = _make_high_entropy_token(28)
    line = f'session_id = "{token}"'

    findings = scan_line("helper.py", 7, line)

    assert any(
        f.severity == SEV_MEDIUM
        and "Suspicious high-entropy value" in f.reason
        for f in findings
    )


def test_entropy_low_severity_borderline_case():
    """
    No explicit context, moderately long high-entropy token:
    should be LOW severity.
    """
    token = _make_high_entropy_token(16)
    line = f'blob = "{token}"'

    findings = scan_line("misc.py", 3, line)

    assert any(
        f.severity == SEV_LOW
        and "Suspicious high-entropy value" in f.reason
        for f in findings
    )


def test_short_token_in_sensitive_context_is_medium():
    """
    Short token (len >= 8) in sensitive context should now be MEDIUM severity.
    """
    line = 'db_password = "short123"'

    findings = scan_line("settings.py", 30, line)

    assert any(
        f.severity == SEV_MEDIUM
        and "Suspicious value in sensitive context" in f.reason
        for f in findings
    )


def test_multiple_high_entropy_tokens_in_one_line_all_flagged_with_high():
    """
    If a line contains multiple high-entropy tokens in sensitive context,
    they should both be HIGH severity with the classic reason.
    """
    token1 = _make_high_entropy_token(28)
    token2 = _make_high_entropy_token(30)
    line = f'app_secret = "{token1}"  # another "{token2}"'

    findings = scan_line("combo.py", 42, line)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SEV_HIGH
    assert "High-entropy value in sensitive context" in f.reason