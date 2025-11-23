# tests/corpus/entropy_cases.py

# SECRET via entropy (true positive, high entropy + sensitive context)
db_password = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"  # safepush: EXPECT_SECRET entropy

# SAFE but string-ish (should NOT block: currently LOW severity, we treat LOW as SAFE in eval)
session_id = "abc123def456ghi789"          # safepush: EXPECT_SAFE entropy

# SECRET but only medium-ish entropy, still in sensitive context
api_key = "devpassword123"                 # safepush: EXPECT_SECRET entropy

# SECRET: long random token with NO explicit context -> still want to block
opaque_token = "Ab9Xy7Qp3Lm5Tn8Zr2Kc4Vw6"  # safepush: EXPECT_SECRET entropy

# SAFE: long-ish but structured version string – low entropy
build_id = "release-2024.11.22-alpha03"    # safepush: EXPECT_SAFE entropy

# SAFE: URL with query params – lots of chars but not a secret by itself
callback_url = "https://example.com/callback?state=abc123xyz"  # safepush: EXPECT_SAFE entropy

# SAFE: comment-style documentation mentioning an example key format, but no real key
doc_aws_format = (
    "Example AWS key format: AKIAxxxxxxxxxxxxxxxx (not real)"  # safepush: EXPECT_SAFE entropy
)

# SECRET: .env-style line with a real-looking high-entropy secret
AWS_SECRET = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"  # safepush: EXPECT_SECRET entropy

# SAFE: docstring-ish example of a Stripe key with short placeholder, not matching pattern or entropy thresholds
stripe_doc_example = 'Example: sk_live_xxxxxxxxxx (demo only)'  # safepush: EXPECT_SAFE entropy
