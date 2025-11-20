"""
scanner.config

Loads SafePush configuration from .safepush.yml / .safepush.json (if present)
and exposes small helper functions used by the scanner logic.

Design goals:
- Best-effort: if config file is missing or invalid, fall back to empty config.
- No hard dependency on PyYAML; we support a simple YAML subset used by this project.
- Loaded once at import time (cheap and predictable).
- Small public API:
    - should_ignore_file(path)
    - should_ignore_line(line)
    - is_allowlisted(token)
    - get_block_severity()
"""

import os
import fnmatch
import json
import hashlib
import re
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # YAML is optional; we have a fallback parser for simple configs.


_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH"}
_PROFILE_TO_SEVERITY = {
    "strict": "LOW",
    "balanced": "MEDIUM",
    "relaxed": "HIGH",
}


# ======================================================================
# Internal config representation
# ======================================================================

class SafePushConfig:
    """
    In-memory representation of .safepush config.

    Fields:
        ignore_paths: list of glob patterns or directory/file prefixes
        ignore_patterns: list of regex strings (compiled at load)
        ignore_lines_with: list of substrings; if any appear in a line, ignore it
        allowlist_hashes: list of literal tokens or "sha256:<hex>" entries
        block_severity: minimum severity that should BLOCK commits/CI
                        ("LOW", "MEDIUM", "HIGH").
                        If not set, defaults via policy_profile or "HIGH".
        policy_profile: optional high-level profile name:
                        "strict" | "balanced" | "relaxed"
    """

    def __init__(
        self,
        ignore_paths: Optional[List[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        ignore_lines_with: Optional[List[str]] = None,
        allowlist_hashes: Optional[List[str]] = None,
        block_severity: Optional[str] = None,
        policy_profile: Optional[str] = None,
    ) -> None:
        self.ignore_paths: List[str] = ignore_paths or []

        # Store both raw and compiled forms of ignore_patterns
        self.ignore_patterns_raw: List[str] = ignore_patterns or []
        self.ignore_patterns: List[re.Pattern[str]] = [
            re.compile(p) for p in self.ignore_patterns_raw
        ]

        self.ignore_lines_with: List[str] = ignore_lines_with or []
        self.allowlist_hashes: List[str] = allowlist_hashes or []

        # Explicit block severity (wins over profile if set)
        if block_severity:
            bs = str(block_severity).strip().upper()
            self.block_severity: Optional[str] = bs if bs in _VALID_SEVERITIES else None
        else:
            self.block_severity = None

        # Optional profile, normalized to lowercase
        if policy_profile:
            pp = str(policy_profile).strip().lower()
            self.policy_profile: Optional[str] = pp if pp in _PROFILE_TO_SEVERITY else None
        else:
            self.policy_profile = None


# ======================================================================
# Loading helpers
# ======================================================================

def _load_yaml_with_fallback(path: str) -> Dict[str, Any]:
    """
    Load a minimal YAML file.

    Priority:
    1. If PyYAML is installed, use yaml.safe_load.
    2. Otherwise, use a tiny, very limited parser that supports exactly
       the structures we use in this project:

           key:
             - "value1"
             - "value2"

       Lines starting with '#' are treated as comments.

    If anything looks wrong, return {} so we fail open (no config)
    rather than blocking commits.
    """
    # Case 1: PyYAML available
    if yaml is not None:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}

    # Case 2: Minimal fallback parser for our simple use-case
    data: Dict[str, Any] = {}
    current_key: Optional[str] = None

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")

                # Skip blanks & comments
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # New top-level key: "key:"
                if not line.startswith(" ") and stripped.endswith(":"):
                    key = stripped[:-1].strip()
                    if key:
                        current_key = key
                        # default to list; fine for our usage
                        if key not in data:
                            data[key] = []
                    continue

                # List item for current key: "  - value"
                if current_key and stripped.startswith("-"):
                    value = stripped[1:].strip()
                    # Strip optional surrounding quotes
                    if (value.startswith('"') and value.endswith('"')) or (
                        value.startswith("'") and value.endswith("'")
                    ):
                        value = value[1:-1]
                    if isinstance(data.get(current_key), list):
                        data[current_key].append(value)
                    continue

                # Anything else is ignored in this minimal parser.
    except Exception:
        return {}

    # Ensure we only return dict-like data
    return data if isinstance(data, dict) else {}


def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _find_config_file() -> Optional[str]:
    """
    Look for a config file in the current working directory:

        .safepush.yml
        .safepush.yaml
        .safepush.json

    In pre-commit + CI, cwd should be the repo root.
    """
    candidates = [
        ".safepush.yml",
        ".safepush.yaml",
        ".safepush.json",
    ]
    for name in candidates:
        if os.path.isfile(name):
            return name
    return None


def _load_config() -> SafePushConfig:
    """
    Load configuration from disk into a SafePushConfig.

    On any error (missing file, parse error), we return an "empty"
    config (no ignores / allowlists) so behavior falls back to strict.
    """
    path = _find_config_file()
    if not path:
        return SafePushConfig()

    if path.endswith((".yml", ".yaml")):
        raw = _load_yaml_with_fallback(path)
    elif path.endswith(".json"):
        raw = _load_json(path)
    else:
        raw = {}

    if not isinstance(raw, dict):
        return SafePushConfig()

    return SafePushConfig(
        ignore_paths=raw.get("ignore_paths", []),
        ignore_patterns=raw.get("ignore_patterns", []),
        ignore_lines_with=raw.get("ignore_lines_with", []),
        allowlist_hashes=raw.get("allowlist_hashes", []),
        block_severity=raw.get("block_severity"),
        policy_profile=raw.get("policy_profile"),
    )


# Single shared config instance used by helpers below.
_CONFIG: SafePushConfig = _load_config()


# ======================================================================
# Public helper functions
# ======================================================================

def should_ignore_file(file_path: str) -> bool:
    """
    Return True if this file should be skipped entirely based on ignore_paths.
    """
    patterns = _CONFIG.ignore_paths
    if not patterns:
        return False

    # Normalize separators and remove leading "./"
    normalized = file_path.replace(os.sep, "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]

    for pattern in patterns:
        # Direct glob match ("tests/**", "*.md", etc.)
        if fnmatch.fnmatch(normalized, pattern):
            return True

        # Bare directory or file path without glob chars
        if not any(ch in pattern for ch in "*?["):
            clean = pattern.rstrip("/")
            # Exact file match
            if normalized == clean:
                return True
            # Directory prefix match: "tests" -> "tests/..."
            if normalized.startswith(clean + "/"):
                return True

    return False


def should_ignore_line(line: str) -> bool:
    """
    Return True if this line should be skipped based on:
      - inline ignore markers (ignore_lines_with)
      - ignore_patterns regexes
    """
    # Check inline markers
    for marker in _CONFIG.ignore_lines_with:
        if marker in line:
            return True

    # Check regex-based ignore patterns
    for regex in _CONFIG.ignore_patterns:
        if regex.search(line):
            return True

    return False


def is_allowlisted(token: str) -> bool:
    """
    Return True if the given token is explicitly allowlisted.
    """
    entries = _CONFIG.allowlist_hashes
    if not entries:
        return False

    token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()

    for entry in entries:
        if entry.startswith("sha256:"):
            expected = entry[len("sha256:") :].strip().lower()
            if token_sha256 == expected:
                return True
        else:
            if token == entry:
                return True

    return False


def get_block_severity() -> str:
    """
    Return the configured minimum severity that should block a commit/CI run.

    Precedence:
      1) block_severity ("LOW"/"MEDIUM"/"HIGH") if explicitly set.
      2) policy_profile ("strict"/"balanced"/"relaxed") mapped to a severity.
      3) Default: "HIGH".
    """
    # 1) Explicit block_severity wins
    bs = getattr(_CONFIG, "block_severity", None)
    if isinstance(bs, str) and bs in _VALID_SEVERITIES:
        return bs

    # 2) Otherwise, use policy_profile if present
    prof = getattr(_CONFIG, "policy_profile", None)
    if isinstance(prof, str):
        sev = _PROFILE_TO_SEVERITY.get(prof)
        if sev in _VALID_SEVERITIES:
            return sev

    # 3) Fallback
    return "HIGH"