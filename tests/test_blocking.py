# tests/test_blocking.py

import pytest

import scanner.config as cfg
from scanner.config import SafePushConfig, get_block_severity
from scanner.core import Finding
import cli.precommit_scan as pre
import cli.ci_scan as ci


def _make_finding(severity: str) -> Finding:
    """Helper to build a minimal Finding for blocking tests."""
    return Finding(
        file="example.py",
        line_no=1,
        snippet='VALUE = "dummy"',
        reason="test finding",
        severity=severity,
    )


@pytest.fixture(autouse=True)
def reset_config():
    """
    Automatically run before & after each test.

    We temporarily replace cfg._CONFIG with a custom SafePushConfig
    and then restore the original after each test.
    """
    original = cfg._CONFIG
    yield
    cfg._CONFIG = original


# ---------------------------------------------------------------------------
# get_block_severity: mapping from config -> effective blocking severity
# ---------------------------------------------------------------------------

def test_default_block_severity_is_high_when_unset():
    # No explicit block_severity or policy_profile
    cfg._CONFIG = SafePushConfig()
    assert get_block_severity() == "HIGH"


def test_block_severity_explicit_overrides_profile():
    # Explicit block_severity wins, even if profile is set
    cfg._CONFIG = SafePushConfig(
        block_severity="LOW",
        policy_profile="relaxed",   # would map to HIGH if used
    )
    assert get_block_severity() == "LOW"


def test_policy_profile_relaxed_maps_to_high():
    cfg._CONFIG = SafePushConfig(policy_profile="relaxed")
    assert get_block_severity() == "HIGH"


def test_policy_profile_balanced_maps_to_medium():
    cfg._CONFIG = SafePushConfig(policy_profile="balanced")
    assert get_block_severity() == "MEDIUM"


def test_policy_profile_strict_maps_to_low():
    cfg._CONFIG = SafePushConfig(policy_profile="strict")
    assert get_block_severity() == "LOW"


def test_invalid_profile_and_invalid_block_severity_fall_back_to_high():
    cfg._CONFIG = SafePushConfig(
        block_severity="WRONG",
        policy_profile="unknown",
    )
    assert get_block_severity() == "HIGH"


# ---------------------------------------------------------------------------
# _should_block: pre-commit behavior vs severity threshold
# ---------------------------------------------------------------------------

def test_precommit_blocks_only_on_high_by_default():
    # default => block_severity == HIGH
    cfg._CONFIG = SafePushConfig()
    assert get_block_severity() == "HIGH"

    assert not pre._should_block([])
    assert not pre._should_block([_make_finding("LOW")])
    assert not pre._should_block([_make_finding("MEDIUM")])
    assert pre._should_block([_make_finding("HIGH")])

    # Mixed severities: presence of HIGH is enough
    findings = [
        _make_finding("LOW"),
        _make_finding("MEDIUM"),
        _make_finding("HIGH"),
    ]
    assert pre._should_block(findings)


def test_precommit_with_balanced_profile_blocks_medium_and_high():
    # balanced -> MEDIUM
    cfg._CONFIG = SafePushConfig(policy_profile="balanced")
    assert get_block_severity() == "MEDIUM"

    assert not pre._should_block([])
    assert not pre._should_block([_make_finding("LOW")])
    assert pre._should_block([_make_finding("MEDIUM")])
    assert pre._should_block([_make_finding("HIGH")])

    # Mixed: LOW + MEDIUM should block
    findings = [
        _make_finding("LOW"),
        _make_finding("MEDIUM"),
    ]
    assert pre._should_block(findings)


def test_precommit_with_strict_profile_blocks_any_severity():
    # strict -> LOW
    cfg._CONFIG = SafePushConfig(policy_profile="strict")
    assert get_block_severity() == "LOW"

    assert not pre._should_block([])

    # Any severity at or above LOW should block
    assert pre._should_block([_make_finding("LOW")])
    assert pre._should_block([_make_finding("MEDIUM")])
    assert pre._should_block([_make_finding("HIGH")])


def test_precommit_block_severity_explicit_low_overrides_profile():
    # Explicit block_severity wins over profile
    cfg._CONFIG = SafePushConfig(
        block_severity="LOW",
        policy_profile="relaxed",
    )
    assert get_block_severity() == "LOW"

    assert pre._should_block([_make_finding("LOW")])
    assert pre._should_block([_make_finding("MEDIUM")])
    assert pre._should_block([_make_finding("HIGH")])


# ---------------------------------------------------------------------------
# _should_block: CI behavior should mirror pre-commit behavior
# ---------------------------------------------------------------------------

def test_ci_blocking_follows_same_threshold_logic():
    # Use balanced profile as a representative case
    cfg._CONFIG = SafePushConfig(policy_profile="balanced")
    assert get_block_severity() == "MEDIUM"

    # No findings
    assert not ci._should_block([])

    # LOW alone -> no block
    assert not ci._should_block([_make_finding("LOW")])

    # MEDIUM or HIGH present -> block
    assert ci._should_block([_make_finding("MEDIUM")])
    assert ci._should_block([_make_finding("HIGH")])

    # Mixed LOW + MEDIUM -> block
    findings = [
        _make_finding("LOW"),
        _make_finding("MEDIUM"),
    ]
    assert ci._should_block(findings)