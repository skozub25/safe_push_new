# cli/ci_scan.py
import os, subprocess, sys, pathlib
from scanner.core import scan_line

def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()

def _changed_files_in_pr() -> list[str] | None:
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if not base_ref:
        return None  # not running in a PR context
    # Ensure we have full history to diff against base
    subprocess.run(["git", "fetch", "origin", base_ref, "--depth=1"], check=False)
    merge_base = _run(["git", "merge-base", f"origin/{base_ref}", "HEAD"])
    out = _run(["git", "diff", "--name-only", f"{merge_base}..HEAD"])
    return [p for p in out.splitlines() if p]

def _tracked_files() -> list[str]:
    out = _run(["git", "ls-files"])
    return [p for p in out.splitlines() if p]

def _scan_paths(paths: list[str]) -> list:
    findings = []
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

def main() -> int:
    changed = _changed_files_in_pr()
    paths = changed if changed else _tracked_files()
    findings = _scan_paths(paths)

    if findings:
        print("Potential secrets detected in CI:\n")
        for f in findings:
            print(f"{f.file}:{f.line_no}: {f.reason}")
            print(f"    {f.snippet}")
        return 1

    print("No secrets found.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
