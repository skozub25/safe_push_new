import re

PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                 # AWS access key ID
    re.compile(r'-----BEGIN (RSA|EC) PRIVATE KEY-----'),
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),         # Stripe secret-style

    re.compile(r'ghp_[A-Za-z0-9]{36}'),                            # GitHub PAT (classic)
    re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,48}'),                 # Slack token (coarse)
    re.compile(r'SK[0-9a-fA-F]{32}'),                              # Twilio secret (SID/Token variant)
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                         # Google API key
    re.compile(r'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+'),  # Azure SB conn string

    # JWT (very coarse): base64url header.payload.signature (header often starts with 'eyJ')
    re.compile(r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),

    # AWS Secret Access Key when assigned near the canonical name (40 base64-ish)
    re.compile(r'aws_secret_access_key[^=\n]*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
]
