# tests/test_dedupe.py

from scanner.core import Finding, _dedupe_by_line


def _make_finding(severity: str, line_no: int = 10) -> Finding:
    return Finding(
        file="example.py",
        line_no=line_no,
        snippet='app_secret = "dummy"',
        reason="test finding",
        severity=severity,
    )


def test_dedupe_keeps_only_highest_severity_for_same_line():
    low = _make_finding("LOW", line_no=10)
    medium = _make_finding("MEDIUM", line_no=10)
    high = _make_finding("HIGH", line_no=10)

    deduped = _dedupe_by_line([low, medium, high])

    # Only one finding for that (file, line, snippet)
    assert len(deduped) == 1
    f = deduped[0]
    assert f.severity == "HIGH"
    assert f.line_no == 10
    assert "test finding" in f.reason


def test_dedupe_does_not_merge_different_lines():
    low_line_10 = _make_finding("LOW", line_no=10)
    high_line_11 = _make_finding("HIGH", line_no=11)

    deduped = _dedupe_by_line([low_line_10, high_line_11])

    # Both lines should be preserved
    assert len(deduped) == 2
    severities = {f.line_no: f.severity for f in deduped}
    assert severities[10] == "LOW"
    assert severities[11] == "HIGH"
