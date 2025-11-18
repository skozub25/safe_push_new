"""
Tests for Stage 1 config behavior:
- ignore_paths
- ignore_lines_with
- ignore_patterns
- allowlist_hashes (literal + sha256)

These are *integration-style* tests:
they verify how scan_line + scanner.config interact,
without touching provider-specific regex tests or entropy math.
"""

import hashlib
import pytest

from scanner import config as cfg
from scanner.config import SafePushConfig
from scanner.core import scan_line


@pytest.fixture(autouse=True)
def reset_config():
    """
    Automatically run before & after each test.

    We temporarily replace cfg._CONFIG with a custom SafePushConfig
    and then restore the original after each test.

    This avoids depending on whatever .safepush.yml the repo may have,
    and keeps tests isolated + deterministic.
    """
    original = cfg._CONFIG
    yield
    cfg._CONFIG = original


def make_findings(file_path: str, line: str):
    """Call scan_line with a fake file/line number."""
    return scan_line(file_path, 10, line)


def test_ignore_paths_skips_entire_file():
    cfg._CONFIG = SafePushConfig(ignore_paths=["ignored_dir/**"])

    # Construct an AWS-like token at runtime (avoid contiguous literal in source)
    token = "AKIA" + "1234567890ABCDE1"
    line = f'API_KEY = "{token}"'

    findings = make_findings("ignored_dir/secrets.py", line)
    assert findings == []  # file-level ignore wins


def test_ignore_lines_with_marker_skips_line():
    cfg._CONFIG = SafePushConfig(ignore_lines_with=["# safepush: ignore"])

    token = "AKIA" + "1234567890ABCDE1"
    line = f'API_KEY = "{token}"  # safepush: ignore'

    findings = make_findings("app/config.py", line)
    assert findings == []  # inline marker suppresses finding


def test_ignore_patterns_suppresses_matching_lines():
    # Build the ignore regex at runtime to avoid raw literal in source
    ignored_literal = "AKIA" + "1234567890ABCDE1"
    cfg._CONFIG = SafePushConfig(ignore_patterns=[ignored_literal])

    line = f'API_KEY = "{ignored_literal}"'
    findings = make_findings("app/config.py", line)
    assert findings == []


def test_allowlist_literal_token_suppresses_specific_secret():
    allowlisted = "AKIA" + "1234567890ABCDE1"

    cfg._CONFIG = SafePushConfig(allowlist_hashes=[allowlisted])

    line = f'API_KEY = "{allowlisted}"'
    findings = make_findings("app/config.py", line)
    assert findings == []  # this exact token is globally allowlisted


def test_allowlist_sha256_suppresses_specific_secret_anywhere():
    token = "sk_live_" + "1234567890" + "abcdefghijklmn"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    cfg._CONFIG = SafePushConfig(allowlist_hashes=[f"sha256:{token_hash}"])

    line = f'STRIPE_SECRET = "{token}"'
    findings = make_findings("payments/keys.py", line)
    assert findings == []  # hashed allowlist prevents this from being flagged
