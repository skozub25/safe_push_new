# scanner/notifier.py

import json
import os
import urllib.request
from typing import List

from .core import Finding


def send_canary_alert(webhook_url: str, findings: List[Finding]) -> None:
    """
    Send a JSON alert to the given webhook URL for one or more canary findings.

    This is best-effort:
    - If webhook_url is empty, does nothing.
    - If the HTTP request fails, we swallow the exception so CI doesn't break
      *because* alerting is down.
    """
    if not webhook_url or not findings:
        return

    payload = {
        "type": "safepush_canary_alert",
        "repo": os.environ.get("GITHUB_REPOSITORY"),
        "commit": os.environ.get("GITHUB_SHA"),
        "actor": os.environ.get("GITHUB_ACTOR"),
        "branch": os.environ.get("GITHUB_REF"),
        "findings": [
            {
                "file": f.file,
                "line": f.line_no,
                "reason": f.reason,
                "severity": f.severity,
                "snippet": f.snippet,
            }
            for f in findings
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        # Fail-open: we don't want to break CI if the webhook is flaky.
        # In a more advanced version, you might log this somewhere.
        pass
