# tests/corpus/pattern_cases.py

# SECRET via provider pattern (AWS key)
aws_key = "AKIA1234567890ABCDE1"  # safepush: EXPECT_SECRET pattern

# SECRET: same AWS key but in env-style assignment
aws_env = 'AWS_ACCESS_KEY_ID="AKIA1234567890ABCDE1"'  # safepush: EXPECT_SECRET pattern

# SAFE: looks a bit like AWS but too short -> should NOT match the pattern
short_awsish = "AKIA123"          # safepush: EXPECT_SAFE pattern

# SECRET via SafePush-specific pattern (still exercises pattern logic)
canary_pattern = "SAFEPUSH_CANARY_EXAMPLE1234"  # safepush: EXPECT_SECRET pattern

# SAFE: looks stripe-ish but is short and should NOT be detected
fake_stripe = "sk_live_demo"  # safepush: EXPECT_SAFE pattern

# SECRET: GitHub PAT
gh_pat = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"  # safepush: EXPECT_SECRET pattern

# SAFE: shortened PAT example in docs – should NOT trigger provider pattern or entropy
gh_doc_example = "Example: ghp_xxxxxxxxxxxxxxxxxxxxxxxx (demo token)"  # safepush: EXPECT_SAFE pattern

# SECRET: generic high-entropy token (no context, but very random)
random_id = "GHP_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"   # safepush: EXPECT_SECRET entropy

# SECRET: SafePush canary token should always be caught as HIGH via pattern
safepush_canary = "SAFEPUSH_CANARY_3F7D9A2BC48E1C6D"  # safepush: EXPECT_SECRET pattern
