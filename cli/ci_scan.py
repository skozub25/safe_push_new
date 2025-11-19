# cli/ci_scan.py
import os
import pathlib
import subprocess
import sys
from typing import List, Optional

from scanner.core import scan_line, Finding
from scanner.config import get_block_severity

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _run(cmd: List[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def _changed_files_in_pr() -> Optional[List[str]]:
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if not base_ref:
        return None  # not running in a PR context

    # Ensure we have full history to diff against base
    subprocess.run(["git", "fetch", "origin", base_ref, "--depth=1"], check=False)
    merge_base = _run(["git", "merge-base", f"origin/{base_ref}", "HEAD"])
    out = _run(["git", "diff", "--name-only", f"{merge_base}..HEAD"])
    return [p for p in out.splitlines() if p]


def _tracked_files() -> List[str]:
    out = _run(["git", "ls-files"])
    return [p for p in out.splitlines() if p]


def _scan_paths(paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for path in paths:
        # Skip obvious binaries by extension (quick heuristic)
        if pathlib.Path(path).suffix.lower() in {".png", ".jpg", ".jpeg", ".pdf", ".ico", ".gif"}:
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                for i, line in enumerate(f, start=1):
                    findings.extend(scan_line(path, i, line))
        except Exception:
            # unreadable/binary → ignore
            pass
    return findings


def _should_block(findings: List[Finding]) -> bool:
    if not findings:
        return False

    block_sev = get_block_severity()
    threshold = SEVERITY_RANK.get(block_sev, SEVERITY_RANK["HIGH"])
    max_found = max(SEVERITY_RANK.get(f.severity, 0) for f in findings)
    return max_found >= threshold


def main() -> int:
    changed = _changed_files_in_pr()
    paths = changed if changed else _tracked_files()
    findings = _scan_paths(paths)

    if findings:
        print("Potential secrets detected in CI:\n")
        print("Severity legend: HIGH = likely real secrets, "
              "MEDIUM = suspicious, LOW = needs review.\n")

        for f in findings:
            print(f"{f.file}:{f.line_no}: [{f.severity}] {f.reason}")
            print(f"    {f.snippet}")

        if _should_block(findings):
            block_sev = get_block_severity()
            print(
                f"\nCI failed: findings at or above blocking severity "
                f"({block_sev}) were detected."
            )
            return 1
        else:
            block_sev = get_block_severity()
            print(
                f"\nCI warnings only: no findings at or above blocking severity "
                f"({block_sev}). Build passing, but please review the "
                "findings above."
            )
            return 0

    print("No secrets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())