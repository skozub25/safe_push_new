import re
from dataclasses import dataclass
from .patterns import PATTERNS
from .entropy import shannon_entropy
from .config import should_ignore_file, should_ignore_line, is_allowlisted

SENSITIVE_HINTS = ["key", "secret", "token", "password", "jwt"]

@dataclass
class Finding:
    file: str
    line_no: int
    snippet: str
    reason: str


def _is_sensitive_context(line: str) -> bool:
    lower = line.lower()
    return any(h in lower for h in SENSITIVE_HINTS)


def _looks_like_secret(token: str) -> bool:
    # Current heuristic: long + high-entropy-ish
    return len(token) >= 24 and shannon_entropy(token) >= 4.0


def scan_line(file_path: str, line_no: int, line: str):
    """
    Scan a single added line and return any findings.

    Stage 1 behavior:
      - Respect config-based ignores:
          * ignore_paths
          * ignore_lines_with
          * ignore_patterns
          * allowlist_hashes
      - Run provider-specific patterns (PATTERNS).
      - Run entropy-based heuristic for high-entropy tokens
        in sensitive contexts.
    """
    findings = []

    # 0) Global ignores: if the file or line is ignored, skip everything.
    if should_ignore_file(file_path):
        return findings

    if should_ignore_line(line):
        return findings

    stripped = line.strip()

    # 1) Known provider patterns
    for pat in PATTERNS:
        for match in pat.finditer(line):
            token = match.group(0)

            # If this exact token is explicitly allowlisted, skip it.
            if is_allowlisted(token):
                continue

            findings.append(Finding(
                file=file_path,
                line_no=line_no,
                snippet=stripped,
                reason="Matches known secret pattern",
            ))

    # 2) High-entropy candidates inside quotes (unknown secrets)
    #    We only consider tokens that look like structured secrets
    #    and appear in a "sensitive" context.
    if _is_sensitive_context(line):
        for token in re.findall(r'["\']([A-Za-z0-9/+_=.-]{16,})["\']', line):
            if is_allowlisted(token):
                continue

            if _looks_like_secret(token):
                findings.append(Finding(
                    file=file_path,
                    line_no=line_no,
                    snippet=stripped,
                    reason="High-entropy value in sensitive context",
                ))

    return findings
