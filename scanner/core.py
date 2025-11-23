import re
from dataclasses import dataclass
from typing import List, Optional

from .patterns import PATTERN_RULES, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from .entropy import shannon_entropy
from .config import should_ignore_file, should_ignore_line, is_allowlisted

SENSITIVE_HINTS = ["key", "secret", "token", "password", "jwt"] # safepush: ignore
SEVERITY_RANK = {SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3}

@dataclass
class Finding:
    file: str
    line_no: int
    snippet: str
    reason: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH"


def _is_sensitive_context(line: str) -> bool:
    lower = line.lower()
    return any(h in lower for h in SENSITIVE_HINTS)


def _classify_entropy_token(token: str, has_sensitive_context: bool) -> Optional[str]:
    """
    Classify a quoted token based on length, entropy, and whether the surrounding
    line looks like it's dealing with secrets.

    Returns:
        "HIGH", "MEDIUM", "LOW", or None if the token should not be flagged.
    """
    length = len(token)
    entropy = shannon_entropy(token)

    # HIGH: strong signal that this is a real secret.
    # - Appears in a sensitive context
    # - Long and high entropy (very random-looking)
    if has_sensitive_context and length >= 24 and entropy >= 4.0:
        return SEV_HIGH

    # MEDIUM: suspicious but less conclusive.
    # (1) Context suggests a secret, but token is shorter / lower entropy,
    if has_sensitive_context and length >= 8:
        return SEV_MEDIUM

    # (2) No explicit context, but token is long and very high entropy.
    if not has_sensitive_context and length >= 24 and entropy >= 4.0:
        return SEV_MEDIUM

    # LOW: smells like a secret, but signal is weaker.
    if not has_sensitive_context and length >= 16 and entropy >= 3.5:
        return SEV_LOW

    return None

def _dedupe_by_line(findings: List[Finding]) -> List[Finding]:
    """
    For each (file, line_no, snippet), keep only the Finding
    with the highest severity. If severities tie, keep the first one seen.
    """
    best: dict[tuple[str, int, str], Finding] = {}

    for f in findings:
        key = (f.file, f.line_no, f.snippet)
        existing = best.get(key)
        if existing is None:
            best[key] = f
            continue

        if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
            best[key] = f

    return list(best.values())

def scan_line(file_path: str, line_no: int, line: str) -> List[Finding]:
    """
    Scan a single line and return any findings.

    Behavior:
      - Respect config-based ignores:
          * ignore_paths
          * ignore_lines_with
          * ignore_patterns
          * allowlist_hashes
      - Run provider-specific patterns (PATTERN_RULES) with per-rule severity.
      - Run entropy-based heuristic for quoted tokens, assigning severity
        based on context + entropy + length.

    NEW: If a line has any provider-pattern matches, we do *not* also
    produce entropy-based findings for that same line. Pattern hits win.
    """
    findings: List[Finding] = []

    # 0) Global ignores: if the file or line is ignored, skip everything.
    if should_ignore_file(file_path):
        return findings

    if should_ignore_line(line):
        return findings

    stripped = line.strip()
    has_context = _is_sensitive_context(line)

    # 1) Known provider patterns
    provider_hit = False
    for rule in PATTERN_RULES:
        for match in rule.regex.finditer(line):
            token = match.group(0)

            # If this exact token is explicitly allowlisted, skip it.
            if is_allowlisted(token):
                continue

            findings.append(
                Finding(
                    file=file_path,
                    line_no=line_no,
                    snippet=stripped,
                    reason=f"Matches {rule.name} pattern",
                    severity=rule.severity,
                )
            )
            provider_hit = True

    # DEDUPE RULE:
    # If this line had any provider-specific matches, we don't also
    # attach entropy-based "suspicious" findings for it.
    if provider_hit:
        return findings

    # 2) Entropy-based candidates inside quotes (unknown secrets)
    for token in re.findall(r'["\']([A-Za-z0-9/+_=.\-]{8,})["\']', line):
        if is_allowlisted(token):
            continue

        severity = _classify_entropy_token(token, has_context)
        if not severity:
            continue

        # Keep old reason text for HIGH-sensitive-context case so existing tests pass
        if has_context and severity == SEV_HIGH:
            reason = "High-entropy value in sensitive context"
        elif has_context:
            reason = "Suspicious value in sensitive context"
        else:
            reason = "Suspicious high-entropy value"

        findings.append(
            Finding(
                file=file_path,
                line_no=line_no,
                snippet=stripped,
                reason=reason,
                severity=severity,
            )
        )

    return _dedupe_by_line(findings)