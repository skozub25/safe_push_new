import re
from dataclasses import dataclass
from typing import List

# Severity levels for pattern-based detections
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"


@dataclass(frozen=True)
class PatternRule:
    """
    Represents a single provider-specific secret pattern.

    Fields:
        name:     Human-readable label shown in findings.
        regex:    Compiled regular expression to match the secret.
        severity: "LOW" | "MEDIUM" | "HIGH"
    """
    name: str
    regex: re.Pattern[str]
    severity: str = SEV_HIGH


# Canonical list of provider-specific patterns with metadata.
# The scanner uses this directly.
PATTERN_RULES: List[PatternRule] = [
    PatternRule(
        name="AWS Access Key ID",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    PatternRule(
        name="RSA/EC Private Key Header",
        regex=re.compile(r"-----BEGIN (RSA|EC) PRIVATE KEY-----"),
    ),
    PatternRule(
        name="Stripe Live Secret Key",
        regex=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    ),
    PatternRule(
        name="GitHub Personal Access Token (classic)",
        regex=re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ),
    PatternRule(
        name="Slack Token",
        regex=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    ),
    PatternRule(
        name="Twilio Secret Token",
        regex=re.compile(r"SK[0-9a-fA-F]{32}"),
    ),
    PatternRule(
        name="Google API Key",
        regex=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    PatternRule(
        name="Azure Service Bus Connection String",
        regex=re.compile(
            r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+"
        ),
    ),
    PatternRule(
        name="JWT (JSON Web Token)",
        regex=re.compile(
            r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        ),
    ),
    PatternRule(
        name="AWS Secret Access Key Assignment",
        regex=re.compile(
            r'aws_secret_access_key[^=\n]*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?'
        ),
    ),
]