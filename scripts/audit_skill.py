Warning: truncated output (original token count: 8936)
Total output lines: 704

#!/usr/bin/env python3
"""Evidence-oriented, read-only static triage for AI skill folders and ZIP files."""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

SCHEMA_VERSION = "2.0"
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_ZIP_RATIO = 200

SCRIPT_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
TEXT_EXTENSIONS = SCRIPT_EXTENSIONS | {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".xml", ".html", ".css", ".csv"}
INSTRUCTION_EXTENSIONS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml"}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "poetry.lock", "pyproject.toml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
}
LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}

INSTRUCTION_RULES = [
    ("SSA-I001", "instruction_integrity", "high", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions", re.I), "Instruction attempts to override authority."),
    ("SSA-I002", "instruction_integrity", "high", re.compile(r"do\s+not\s+(?:tell|inform|show)\s+(?:the\s+)?user", re.I), "Instruction may conceal material behavior from the user."),
    ("SSA-I003", "data_exfiltration", "critical", re.compile(r"(?:send|upload|exfiltrat\w*)[^\n]{0,100}(?:secret|token|credential|private\s+key)", re.I), "Instruction links external transfer to sensitive data."),
    ("SSA-I004", "control_bypass", "high", re.compile(r"(?:disable|bypass|evade)[^\n]{0,80}(?:audit|approval|sandbox|security|permission)", re.I), "Instruction may bypass a se…7936 tokens truncated…space:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="Local skill directory or ZIP to inspect")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="Write report outside the candidate; stdout when omitted")
    parser.add_argument("--baseline", type=Path, help="Previous JSON report for a delta review")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-text-bytes", type=int, default=DEFAULT_MAX_TEXT_BYTES)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output and output_is_inside_candidate(args.candidate, args.output):
        print("error: --output must be outside the candidate to preserve read-only scope", file=sys.stderr)
        return 2
    limits = {
        "max_files": args.max_files,
        "max_file_bytes": args.max_file_bytes,
        "max_total_bytes": args.max_total_bytes,
        "max_text_bytes": args.max_text_bytes,
    }
    if any(value <= 0 for value in limits.values()):
        print("error: scan limits must be positive", file=sys.stderr)
        return 2
    try:
        report = analyze(args.candidate, limits, args.baseline)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.format == "json" else render_markdown(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
