"""Build the report from report.template.md, expanding <<<INCLUDE:path:lang>>> markers.

Keeps the appendix and the quoted test output identical to the submitted files.

    python3 scripts/build_report.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "report" / "report.template.md"
REPORT = ROOT / "report" / "CSC8214-Report.md"
MARKER = re.compile(r"<<<INCLUDE:([^:>]+):([^>]+)>>>")


def expand(match: re.Match[str]) -> str:
    path, language = match.group(1), match.group(2)
    body = (ROOT / path).read_text(encoding="utf-8").rstrip()
    return f"```{language}\n{body}\n```"


def main() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    count = len(MARKER.findall(text))
    REPORT.write_text(MARKER.sub(expand, text), encoding="utf-8")
    print(f"built {REPORT.relative_to(ROOT)} with {count} include(s)")


if __name__ == "__main__":
    main()
