import re
from scanner.patterns import PATTERNS

def _has_match(regex: str, text: str) -> bool:
    pattern = re.compile(regex)
    return bool(pattern.search(text))

def test_aws_access_key_pattern_matches_valid_and_rejects_invalid():
    aws_re = r'AKIA[0-9A-Z]{16}'

    # Build token at runtime so the raw source does not contain a contiguous AKIA key
    token_valid = "AKIA" + "1234567890ABCDE1"
    assert _has_match(aws_re, token_valid)

    assert not _has_match(aws_re, 'AKIA123')                 # too short
    assert not _has_match(aws_re, 'akia1234567890ABCDE1')    # lowercase

def test_rsa_private_key_header_pattern_matches_only_rsa_ec():
    pem_re = r'-----BEGIN (RSA|EC) PRIVATE KEY-----'

    # Construct headers at runtime to avoid exact header literals in source
    rsa_hdr = "-----BEGIN " + "RSA" + " PRIVATE KEY-----"
    ec_hdr  = "-----BEGIN " + "EC"  + " PRIVATE KEY-----"
    plain   = "-----BEGIN PRIVATE KEY-----"

    assert _has_match(pem_re, rsa_hdr)
    assert _has_match(pem_re, ec_hdr)
    assert not _has_match(pem_re, plain)

def test_stripe_live_key_pattern_matches_valid():
    stripe_re = r'sk_live_[0-9a-zA-Z]{24,}'

    # Construct at runtime so file never contains a full pattern match
    token_valid = "sk_live_" + "1234567890" + "abcdefghijklmn"
    assert _has_match(stripe_re, token_valid)

    assert not _has_match(stripe_re, 'sk_live_short')

def test_core_patterns_are_present_in_PATTERNS():
    sources = {p.pattern for p in PATTERNS}

    assert r'AKIA[0-9A-Z]{16}' in sources
    assert r'-----BEGIN (RSA|EC) PRIVATE KEY-----' in sources
    assert r'sk_live_[0-9a-zA-Z]{24,}' in sources

def test_github_pat_pattern():
    pat = r'ghp_[A-Za-z0-9]{36}'
    token = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"  # 36 chars
    assert _has_match(pat, token)
    assert not _has_match(pat, "ghp_short")

def test_slack_token_pattern():
    pat = r'xox[baprs]-[A-Za-z0-9-]{10,48}'
    token = "xoxb-" + "a1b2c3d4e5-67890abcDEF"
    assert _has_match(pat, token)
    assert not _has_match(pat, "xoxq-123")  # invalid product letter

def test_twilio_secret_pattern():
    pat = r'SK[0-9a-fA-F]{32}'
    token = "SK" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    assert _has_match(pat, token)
    assert not _has_match(pat, "SK1234")  # too short

def test_google_api_key_pattern():
    pat = r'AIza[0-9A-Za-z\-_]{35}'
    token = "AIza" + "AbCdEfGhIjKlMnOp-QR_stUvWxYz0123456"
    assert _has_match(pat, token)
    assert not _has_match(pat, "AIzb" + "x"*35)  # wrong prefix

def test_azure_service_bus_conn_string_pattern():
    pat = r'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+'
    cs = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=" + "ABCDEF1234567890"
    assert _has_match(pat, cs)
    assert not _has_match(pat, "Endpoint=https://example;SharedAccessKeyName=x;SharedAccessKey=y")  # not sb://

def test_jwt_pattern_coarse():
    pat = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    header  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"       # {"alg":"HS256","typ":"JWT"}
    payload = "eyJ1c2VySWQiOjEyMywicm9sZSI6InRlc3QifQ"     # {"userId":123,"role":"test"}
    sig     = "dGVzdHNpZ25hdHVyZQ"                         # "testsignature" (dummy)
    jwt = f"{header}.{payload}.{sig}"
    assert _has_match(pat, jwt)
    assert not _has_match(pat, "eyJ-only-two.parts")

def test_aws_secret_access_key_assignment_pattern():
    pat = r'aws_secret_access_key[^=\n]*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?'
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"  # 40 chars total (dummy)
    line = f'aws_secret_access_key = "{secret}"'
    assert _has_match(pat, line)
    assert not _has_match(pat, 'aws_secret_access_key = "short"')

def test_new_patterns_present_in_PATTERNS():
    sources = {p.pattern for p in PATTERNS}
    assert r'ghp_[A-Za-z0-9]{36}' in sources
    assert r'xox[baprs]-[A-Za-z0-9-]{10,48}' in sources
    assert r'SK[0-9a-fA-F]{32}' in sources
    assert r'AIza[0-9A-Za-z\-_]{35}' in sources
    assert r'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+' in sources
    assert r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' in sources
    assert r'aws_secret_access_key[^=\n]*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?' in sources
