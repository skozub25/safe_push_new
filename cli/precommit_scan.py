import subprocess
import sys
from typing import List

from scanner.core import scan_line, Finding


def get_staged_diff() -> str:
    cmd = ["git", "diff", "--cached", "--unified=0"]
    return subprocess.check_output(cmd, text=True)


def main() -> None:
    print("Scanning for secrets in staged changes...")
    diff = get_staged_diff()
    findings: List[Finding] = []

    current_file: str | None = None
    line_no: int | None = None

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            try:
                plus_part = line.split("+")[1].split(" ")[0]
                start = int(plus_part.split(",")[0])
                line_no = start - 1
            except Exception:
                line_no = None
        elif line.startswith("+") and not line.startswith("+++"):
            if current_file is not None and line_no is not None:
                line_no += 1
                code_line = line[1:]  # strip '+'
                findings.extend(scan_line(current_file, line_no, code_line))

    if findings:
        print("\nPotential secrets detected:\n")
        print("Severity legend: HIGH = likely real secrets, "
              "MEDIUM = suspicious, LOW = needs review.\n")

        for f in findings:
            print(f"{f.file}:{f.line_no}: [{f.severity}] {f.reason}")
            print(f"    {f.snippet}")

        print(
            "\nCommit aborted. Remove/rotate these values or mark safe "
            "via config/allowlist, then try again."
        )
        # DO NOT create this commit
        sys.exit(1)

    # no findings: allow commit
    print("No secrets found in staged changes.")
    sys.exit(0)


if __name__ == "__main__":
    main()