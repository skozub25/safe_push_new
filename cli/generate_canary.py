# cli/generate_canary.py

import random
import string
import sys

CANARY_PREFIX = "SAFEPUSH_CANARY_"
ALPHABET = string.ascii_uppercase + string.digits
TOKEN_LEN = 16


def generate_canary() -> str:
    rand = "".join(random.choice(ALPHABET) for _ in range(TOKEN_LEN))
    return CANARY_PREFIX + rand


def main() -> int:
    token = generate_canary()
    print(token)
    print(
        "\nThis is a SafePush canary token. "
        "Commit it in a non-sensitive place (e.g., a test file) to verify that "
        "SafePush and other secret scanners are working. "
        "It should always be flagged as HIGH severity."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
