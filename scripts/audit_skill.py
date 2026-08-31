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
    ("SSA-I004", "control_bypass", "high", re.compile(r"(?:disable|bypass|evade)[^\n]{0,80}(?:audit|approval|sandbox|security|permission)", re.I), "Instruction may bypass a security control."),
    ("SSA-I005", "self_modification", "medium", re.compile(r"(?:self[- ]modify|rewrite\s+this\s+skill|silently\s+update)", re.I), "Instruction may change durable behavior without review."),
]

SCRIPT_LINE_RULES = [
    ("SSA-C101", "destructive_action", "high", re.compile(r"\brm\s+-rf\b|\bRemove-Item\b[^\n]*\b-Recurse\b[^\n]*\b-Force\b", re.I), "Destructive recursive deletion primitive."),
    ("SSA-C102", "remote_bootstrap", "high", re.compile(r"(?:curl|wget)[^\n|]{0,300}\|\s*(?:sh|bash|zsh)\b", re.I), "Remote content is piped to a shell."),
    ("SSA-C103", "dynamic_execution", "high", re.compile(r"\b(?:eval|Invoke-Expression)\s*\(", re.I), "Dynamic code or command evaluation."),
    ("SSA-C104", "command_execution", "high", re.compile(r"\bchild_process\.(?:exec|spawn)|\bshell\s*:\s*true", re.I), "External command execution capability."),
    ("SSA-C105", "privilege_request", "high", re.compile(r"\bsudo\b|\bchmod\s+777\b|Start-Process[^\n]+-Verb\s+RunAs", re.I), "Privilege escalation or unsafe permission request."),
]

SECRET_RULES = [
    ("SSA-S001", "private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SSA-S002", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("SSA-S003", "github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b")),
    ("SSA-S004", "generic_secret_assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*[\"'][^\"'\n]{12,}[\"']")),
]

URL_RE = re.compile(r"https?://[^\s<>'\"`]+", re.I)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{240,}={0,2}(?![A-Za-z0-9+/=])")
PINNED_NPM_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class AuditState:
    def __init__(self, target: Path, kind: str, limits: dict[str, int]) -> None:
        self.target = target
        self.kind = kind
        self.limits = limits
        self.files: list[dict] = []
        self.findings: list[dict] = []
        self.unresolved: list[dict] = []
        self.exclusions: list[dict] = []
        self.endpoints: set[tuple[str, str]] = set()
        self._finding_keys: set[tuple] = set()
        self._texts: dict[str, str] = {}
        self._next_id = 1

    def add_finding(
        self,
        rule_id: str,
        category: str,
        severity: str,
        path: str,
        message: str,
        *,
        line: int | None = None,
        confidence: str = "medium",
        fingerprint: str | None = None,
        remediation: str = "Establish reachability, purpose, and least-privilege controls before approval.",
    ) -> None:
        key = (rule_id, path, line, fingerprint)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        finding = {
            "id": f"F-{self._next_id:04d}",
            "rule_id": rule_id,
            "evidence_class": "observed",
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "path": path,
            "line": line,
            "message": message,
            "remediation": remediation,
        }
        if fingerprint:
            finding["redacted_fingerprint"] = fingerprint
        self._next_id += 1
        self.findings.append(finding)

    def add_unresolved(self, path: str, reason: str) -> None:
        self.unresolved.append({"path": path, "reason": reason})


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def content_kind(path: str, data: bytes) -> str:
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(path).suffix.lower()
    head = data[:8]
    if name == "skill.md":
        return "skill_instructions"
    if name in MANIFEST_NAMES:
        return "dependency_or_manifest"
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF") or head[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        return "native_binary"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"\x1f\x8b"):
        return "archive"
    if suffix in SCRIPT_EXTENSIONS or data.startswith(b"#!"):
        return "script"
    if suffix in TEXT_EXTENSIONS and b"\x00" not in data[:8192]:
        return "text"
    if b"\x00" in data[:8192]:
        return "opaque_binary"
    return "other"


def scan_instruction_text(state: AuditState, path: str, text: str) -> None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in INSTRUCTION_EXTENSIONS and PurePosixPath(path).name.lower() != "skill.md":
        return
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule_id, category, severity, pattern, message in INSTRUCTION_RULES:
            if pattern.search(line):
                state.add_finding(rule_id, category, severity, path, message, line=line_no, confidence="high")


def scan_urls_and_secrets(state: AuditState, path: str, text: str) -> None:
    for match in URL_RE.finditer(text):
        parsed = urlsplit(match.group(0).rstrip(".,);]"))
        if parsed.hostname:
            state.endpoints.add((parsed.scheme.lower(), parsed.hostname.lower()))
    for rule_id, secret_type, pattern in SECRET_RULES:
        for match in pattern.finditer(text):
            fingerprint = sha256_bytes(match.group(0).encode("utf-8", errors="replace"))[:16]
            line = text.count("\n", 0, match.start()) + 1
            state.add_finding(
                rule_id,
                "embedded_secret",
                "high",
                path,
                f"Potential embedded {secret_type}; value redacted.",
                line=line,
                confidence="medium",
                fingerprint=fingerprint,
                remediation="Remove the value, rotate it if real, and use scoped secret storage.",
            )
    for match in BASE64_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        fingerprint = sha256_bytes(match.group(0).encode("ascii"))[:16]
        state.add_finding(
            "SSA-O001", "encoded_content", "medium", path,
            "Large encoded blob requires decoding and provenance review.", line=line,
            fingerprint=fingerprint,
            remediation="Decode in an isolated analysis step, identify its type, and review it before approval.",
        )


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def scan_python(state: AuditState, path: str, text: str) -> None:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        state.add_unresolved(path, f"Python parse failed at line {exc.lineno}; code review incomplete")
        state.add_finding("SSA-P001", "unparsed_code", "medium", path, "Python source could not be parsed.", line=exc.lineno)
        return

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    call_rules = {
        "os.system": ("SSA-P101", "command_execution", "high"),
        "subprocess.run": ("SSA-P102", "command_execution", "high"),
        "subprocess.call": ("SSA-P102", "command_execution", "high"),
        "subprocess.Popen": ("SSA-P102", "command_execution", "high"),
        "eval": ("SSA-P103", "dynamic_execution", "high"),
        "exec": ("SSA-P103", "dynamic_execution", "high"),
        "compile": ("SSA-P103", "dynamic_execution", "medium"),
        "importlib.import_module": ("SSA-P104", "dynamic_loading", "medium"),
        "requests.get": ("SSA-P201", "network_egress", "medium"),
        "requests.post": ("SSA-P201", "network_egress", "medium"),
        "urllib.request.urlopen": ("SSA-P201", "network_egress", "medium"),
        "socket.socket": ("SSA-P202", "network_egress", "medium"),
        "os.getenv": ("SSA-P203", "secret_access", "medium"),
        "os.environ.get": ("SSA-P203", "secret_access", "medium"),
        "Path.home": ("SSA-P301", "broad_file_access", "medium"),
        "pathlib.Path.home": ("SSA-P301", "broad_file_access", "medium"),
        "os.walk": ("SSA-P302", "recursive_file_access", "medium"),
        "os.scandir": ("SSA-P302", "recursive_file_access", "medium"),
        "shutil.rmtree": ("SSA-P401", "destructive_action", "high"),
        "os.remove": ("SSA-P402", "destructive_action", "high"),
        "os.unlink": ("SSA-P402", "destructive_action", "high"),
        "Path.unlink": ("SSA-P402", "destructive_action", "high"),
        "os.setuid": ("SSA-P501", "privilege_change", "high"),
        "os.chmod": ("SSA-P502", "permission_change", "medium"),
        "Path.write_text": ("SSA-P601", "file_write", "low"),
        "Path.write_bytes": ("SSA-P601", "file_write", "low"),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            first, separator, remainder = name.partition(".")
            if first in aliases:
                name = aliases[first] + (separator + remainder if separator else "")
            selected = call_rules.get(name)
            if not selected and name.startswith("subprocess."):
                selected = ("SSA-P102", "command_execution", "high")
            if not selected and name.startswith("requests."):
                selected = ("SSA-P201", "network_egress", "medium")
            if not selected and name.endswith((".read_text", ".read_bytes")):
                selected = ("SSA-P602", "file_read", "low")
            if not selected and name.endswith((".write_text", ".write_bytes")):
                selected = ("SSA-P601", "file_write", "low")
            if not selected and name.endswith(".unlink"):
                selected = ("SSA-P402", "destructive_action", "high")
            if selected:
                rule_id, category, severity = selected
                state.add_finding(
                    rule_id, category, severity, path,
                    f"Python capability observed: {name}().",
                    line=getattr(node, "lineno", None), confidence="high",
                )
        elif isinstance(node, ast.Subscript) and dotted_name(node.value) == "os.environ":
            state.add_finding(
                "SSA-P701", "secret_access", "medium", path,
                "Python reads an environment variable.", line=getattr(node, "lineno", None), confidence="high",
            )


def scan_script_lines(state: AuditState, path: str, text: str) -> None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        scan_python(state, path, text)
        return
    if suffix not in SCRIPT_EXTENSIONS and not text.startswith("#!"):
        return
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule_id, category, severity, pattern, message in SCRIPT_LINE_RULES:
            if pattern.search(line):
                state.add_finding(rule_id, category, severity, path, message, line=line_no, confidence="high")


def analyze_manifests(state: AuditState) -> None:
    paths = set(state._texts)
    for path, text in state._texts.items():
        name = PurePosixPath(path).name
        parent = str(PurePosixPath(path).parent)
        if name == "package.json":
            try:
                package = json.loads(text)
            except json.JSONDecodeError as exc:
                state.add_unresolved(path, "package.json is invalid JSON")
                state.add_finding("SSA-N001", "manifest_integrity", "high", path, "package.json cannot be parsed.", line=exc.lineno, confidence="high")
                continue
            scripts = package.get("scripts") if isinstance(package, dict) else None
            if isinstance(scripts, dict):
                for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"):
                    command = scripts.get(hook)
                    if isinstance(command, str) and command.strip():
                        state.add_finding(
                            "SSA-N101", "lifecycle_hook", "high", path,
                            f"npm lifecycle hook declared: {hook}; command content withheld from summary.",
                            confidence="high", fingerprint=sha256_bytes(command.encode())[:16],
                            remediation="Review the complete hook and dependencies; do not run it during static audit.",
                        )
            dependencies = {}
            for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                value = package.get(key) if isinstance(package, dict) else None
                if isinstance(value, dict):
                    dependencies.update(value)
            lock_present = any((str(PurePosixPath(parent) / lock) if parent != "." else lock) in paths for lock in LOCK_NAMES)
            if dependencies and not lock_present:
                state.add_finding("SSA-N201", "supply_chain", "medium", path, "Node dependencies are declared without a recognized lockfile.", confidence="high")
            for dep, version in dependencies.items():
                if not isinstance(version, str):
                    continue
                if version.startswith(("git+", "git://", "http://", "https://", "file:", "github:")):
                    state.add_finding("SSA-N202", "supply_chain", "high", path, f"Dependency {dep!r} uses a non-registry or remote source.", confidence="high")
                elif not lock_present and not PINNED_NPM_RE.fullmatch(version):
                    state.add_finding("SSA-N203", "supply_chain", "medium", path, f"Dependency {dep!r} is not exactly pinned and no lockfile is present.", confidence="high")
        elif name == "requirements.txt":
            for line_no, raw in enumerate(text.splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(("-r", "--require-hashes")):
                    continue
                if "==" not in line or "--hash=" not in line:
                    state.add_finding(
                        "SSA-R201", "supply_chain", "medium", path,
                        "Python requirement is not both exactly pinned and hash-locked.",
                        line=line_no, confidence="high",
                    )
        config_suffix = PurePosixPath(path).suffix.lower()
        known_tool_config = name in {"openai.yaml", "openai.yml", "mcp.json", "claude_desktop_config.json"}
        declared_mcp = config_suffix in {".json", ".yaml", ".yml", ".toml"} and "mcpServers" in text
        if (known_tool_config and re.search(r"(?im)^\s*(?:tools|dependencies)\s*:", text)) or declared_mcp:
            state.add_finding(
                "SSA-M101", "tool_or_mcp_authority", "medium", path,
                "Tool or MCP authority declaration requires permission and destination review.", confidence="high",
            )
        if path.startswith(".github/workflows/") and re.search(r"(?im)^\s*pull_request_target\s*:", text):
            state.add_finding("SSA-G101", "workflow_authority", "high", path, "GitHub workflow uses pull_request_target.", confidence="high")
        if path.startswith(".github/workflows/") and re.search(r"(?im)^\s*permissions\s*:\s*write-all\s*$", text):
            state.add_finding("SSA-G102", "workflow_authority", "high", path, "GitHub workflow grants write-all permissions.", confidence="high")


def analyze_skill_structure(state: AuditState) -> None:
    paths = set(state._texts)
    skill_paths = sorted(path for path in paths if PurePosixPath(path).name.lower() == "skill.md")
    if not skill_paths:
        state.add_finding(
            "SSA-K001", "skill_structure", "medium", ".",
            "No SKILL.md was found; confirm whether this is an installable skill package.", confidence="high",
        )
        return
    for path in skill_paths:
        text = state._texts[path]
        frontmatter = re.match(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", text, flags=re.S)
        if not frontmatter:
            state.add_finding("SSA-K002", "skill_structure", "high", path, "SKILL.md has no valid YAML frontmatter boundary.", confidence="high")
        else:
            metadata = frontmatter.group(1)
            if not re.search(r"(?m)^name\s*:\s*[^\s].*$", metadata):
                state.add_finding("SSA-K003", "skill_structure", "high", path, "SKILL.md frontmatter has no non-empty name.", confidence="high")
            if not re.search(r"(?m)^description\s*:\s*[^\s].*$", metadata):
                state.add_finding("SSA-K004", "skill_structure", "high", path, "SKILL.md frontmatter has no non-empty description.", confidence="high")
        parent = PurePosixPath(path).parent
        for link in re.findall(r"\[[^\]]+\]\(([^)\s]+)", text):
            if link.startswith(("#", "http://", "https://", "mailto:")):
                continue
            resolved = (parent / link).as_posix()
            if ".." in PurePosixPath(resolved).parts:
                state.add_finding("SSA-K005", "skill_structure", "medium", path, "SKILL.md contains a parent-directory reference.", confidence="high")
            elif resolved not in paths:
                state.add_finding("SSA-K006", "skill_structure", "medium", path, f"Referenced local file is missing: {resolved}.", confidence="high")


def process_bytes(state: AuditState, path: str, data: bytes, *, size: int, sha256: str, executable: bool = False) -> None:
    kind = content_kind(path, data)
    record = {
        "path": path,
        "size_bytes": size,
        "sha256": sha256,
        "classification": kind,
        "executable": executable,
        "hidden": any(part.startswith(".") and part not in {".", ".."} for part in PurePosixPath(path).parts),
    }
    state.files.append(record)
    if kind in {"native_binary", "opaque_binary"}:
        state.add_finding(
            "SSA-B001", "opaque_or_native_binary", "high", path,
            "Binary content requires platform-specific review and provenance validation.", confidence="high",
        )
    if kind == "archive":
        state.add_finding("SSA-A001", "nested_archive", "medium", path, "Nested archive requires a separate bounded inspection.", confidence="high")
    if executable and kind not in {"script", "native_binary"}:
        state.add_finding("SSA-X001", "unexpected_executable", "high", path, "File is executable but its content type is unexpected.", confidence="high")
    if len(data) > state.limits["max_text_bytes"]:
        if kind in {"script", "text", "skill_instructions", "dependency_or_manifest"}:
            state.add_unresolved(path, "Text content exceeds scan limit")
        return
    if kind in {"script", "text", "skill_instructions", "dependency_or_manifest", "other"} and b"\x00" not in data[:8192]:
        text = data.decode("utf-8", errors="replace")
        state._texts[path] = text
        scan_instruction_text(state, path, text)
        scan_urls_and_secrets(state, path, text)
        scan_script_lines(state, path, text)


def analyze_directory(state: AuditState) -> None:
    total = 0
    seen = 0
    for current, dirs, names in os.walk(state.target, followlinks=False):
        current_path = Path(current)
        retained_dirs = []
        for dirname in sorted(dirs):
            path = current_path / dirname
            rel = path.relative_to(state.target).as_posix()
            if path.is_symlink():
                state.add_finding("SSA-L001", "symlink", "high", rel, "Directory symlink is not followed.", confidence="high")
            elif dirname == ".git":
                state.exclusions.append({"path": rel, "reason": "VCS metadata excluded; working-tree content remains in scope"})
            else:
                retained_dirs.append(dirname)
        dirs[:] = retained_dirs
        for name in sorted(names):
            path = current_path / name
            rel = path.relative_to(state.target).as_posix()
            seen += 1
            if seen > state.limits["max_files"]:
                state.add_unresolved(rel, "File-count limit exceeded; remaining inventory incomplete")
                return
            try:
                info = path.lstat()
            except OSError as exc:
                state.add_unresolved(rel, f"Metadata read failed: {exc.__class__.__name__}")
                continue
            if stat.S_ISLNK(info.st_mode):
                state.add_finding("SSA-L002", "symlink", "high", rel, "File symlink is not followed.", confidence="high")
                continue
            if not stat.S_ISREG(info.st_mode):
                state.add_unresolved(rel, "Non-regular filesystem object not inspected")
                continue
            total += info.st_size
            if total > state.limits["max_total_bytes"]:
                state.add_unresolved(rel, "Total-byte limit exceeded; remaining inventory incomplete")
                return
            if info.st_size > state.limits["max_file_bytes"]:
                try:
                    digest = sha256_file(path)
                except OSError:
                    digest = None
                state.files.append({"path": rel, "size_bytes": info.st_size, "sha256": digest, "classification": "oversized", "executable": bool(info.st_mode & 0o111), "hidden": name.startswith(".")})
                state.add_unresolved(rel, "File exceeds per-file inspection limit")
                continue
            try:
                data = path.read_bytes()
            except OSError as exc:
                state.add_unresolved(rel, f"File read failed: {exc.__class__.__name__}")
                continue
            process_bytes(state, rel, data, size=info.st_size, sha256=sha256_bytes(data), executable=bool(info.st_mode & 0o111))


def zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)


def analyze_zip(state: AuditState) -> None:
    state.exclusions.append({"path": state.target.name, "reason": "ZIP inspected in place; nothing extracted"})
    try:
        archive = zipfile.ZipFile(state.target)
    except (OSError, zipfile.BadZipFile) as exc:
        state.add_unresolved(state.target.name, f"ZIP open failed: {exc.__class__.__name__}")
        return
    with archive:
        infos = archive.infolist()
        names = Counter(info.filename for info in infos)
        for name, count in names.items():
            if count > 1:
                state.add_finding("SSA-Z001", "archive_integrity", "high", name, "ZIP contains duplicate entry names.", confidence="high")
        if len(infos) > state.limits["max_files"]:
            state.add_unresolved(state.target.name, "ZIP file-count limit exceeded")
            return
        total = sum(info.file_size for info in infos)
        if total > state.limits["max_total_bytes"]:
            state.add_unresolved(state.target.name, "ZIP uncompressed-size limit exceeded")
            return
        for info in infos:
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or re.match(r"^[A-Za-z]:/", name) or ".." in parts:
                state.add_finding("SSA-Z002", "archive_path_traversal", "high", name, "ZIP entry has an unsafe extraction path.", confidence="high")
                continue
            if info.is_dir():
                continue
            if zip_is_symlink(info):
                state.add_finding("SSA-Z003", "symlink", "high", name, "ZIP entry is a symlink.", confidence="high")
                continue
            if info.flag_bits & 0x1:
                state.add_unresolved(name, "Encrypted ZIP entry cannot be inspected")
                continue
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > 1024 * 1024 and ratio > MAX_ZIP_RATIO:
                state.add_finding("SSA-Z004", "decompression_bomb", "high", name, "ZIP entry has an extreme compression ratio.", confidence="high")
                state.add_unresolved(name, "Entry not decompressed")
                continue
            if info.file_size > state.limits["max_file_bytes"]:
                state.add_unresolved(name, "ZIP entry exceeds per-file inspection limit")
                continue
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                state.add_unresolved(name, f"ZIP entry read failed: {exc.__class__.__name__}")
                continue
            process_bytes(state, name, data, size=info.file_size, sha256=sha256_bytes(data), executable=bool((info.external_attr >> 16) & 0o111))


def compute_tree_digest(files: list[dict]) -> str | None:
    if any(not item.get("sha256") for item in files):
        return None
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda value: value["path"]):
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def compare_baseline(report: dict, baseline_path: Path) -> dict:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old = {item["path"]: item.get("sha256") for item in baseline.get("inventory", {}).get("files", [])}
    new = {item["path"]: item.get("sha256") for item in report.get("inventory", {}).get("files", [])}
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "modified": sorted(path for path in set(old) & set(new) if old[path] != new[path]),
        "unchanged_count": sum(1 for path in set(old) & set(new) if old[path] == new[path]),
    }


def disposition(state: AuditState) -> str:
    if state.unresolved:
        return "INCONCLUSIVE — INVENTORY OR EVIDENCE INCOMPLETE"
    severities = {finding["severity"] for finding in state.findings}
    if severities & {"critical", "high", "medium"}:
        return "HOLD / REVIEW REQUIRED"
    return "STATIC GATES PASSED — MANUAL REVIEW REQUIRED"


def analyze(target: Path, limits: dict[str, int], baseline: Path | None = None) -> dict:
    resolved = target.resolve()
    if resolved.is_dir():
        kind = "directory"
    elif resolved.is_file() and zipfile.is_zipfile(resolved):
        kind = "zip"
    else:
        raise ValueError("candidate must be an existing directory or ZIP file")
    state = AuditState(resolved, kind, limits)
    target_sha = sha256_file(resolved) if kind == "zip" else None
    if kind == "directory":
        analyze_directory(state)
    else:
        analyze_zip(state)
    analyze_manifests(state)
    analyze_skill_structure(state)
    counts = Counter(item["classification"] for item in state.files)
    capability_counts = Counter(finding["category"] for finding in state.findings)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "tool": "skill-safety-audit static scanner",
        "mode": "read-only candidate inspection; no candidate code executed",
        "candidate": {"path": str(resolved), "kind": kind, "archive_sha256": target_sha},
        "limits": limits,
        "inventory": {
            "file_count": len(state.files),
            "total_bytes": sum(item["size_bytes"] for item in state.files),
            "by_classification": dict(sorted(counts.items())),
            "tree_sha256": compute_tree_digest(state.files),
            "files": sorted(state.files, key=lambda item: item["path"]),
        },
        "network_destinations": [{"scheme": scheme, "host": host} for scheme, host in sorted(state.endpoints)],
        "capability_summary": dict(sorted(capability_counts.items())),
        "findings": state.findings,
        "unresolved": state.unresolved,
        "excluded_scope": state.exclusions,
        "preliminary_disposition": disposition(state),
        "approval_statement": "This scanner never approves installation. Apply the manual methodology and bind any approval to this exact tree/archive digest.",
        "limitations": [
            "Static analysis cannot prove absence of malicious or time-gated behavior.",
            "A rule match establishes a review lead, not malicious intent or runtime reachability.",
            "Remote dependency contents, services, and future updates are not executed or trusted by this scan.",
        ],
    }
    if baseline:
        try:
            report["delta"] = compare_baseline(report, baseline)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            report["delta"] = {"error": f"Baseline comparison failed: {exc.__class__.__name__}"}
            report["preliminary_disposition"] = "INCONCLUSIVE — BASELINE COULD NOT BE VERIFIED"
    return report


def render_markdown(report: dict) -> str:
    inv = report["inventory"]
    lines = [
        "# Skill Safety Audit — Static Triage",
        "",
        f"**Preliminary disposition:** {report['preliminary_disposition']}",
        "",
        f"- Candidate: `{report['candidate']['path']}`",
        f"- Kind: `{report['candidate']['kind']}`",
        f"- Files inventoried: {inv['file_count']}",
        f"- Tree SHA-256: `{inv['tree_sha256'] or 'incomplete'}`",
        f"- Findings: {len(report['findings'])}",
        f"- Unresolved items: {len(report['unresolved'])}",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No automated findings. Manual approval gates still apply.")
    else:
        lines.extend(["| ID | Severity | Rule | Location | Observation |", "| --- | --- | --- | --- | --- |"])
        for item in report["findings"]:
            location = item["path"] + (f":{item['line']}" if item.get("line") else "")
            message = item["message"].replace("|", "\\|")
            lines.append(f"| {item['id']} | {item['severity']} | {item['rule_id']} | `{location}` | {message} |")
    lines.extend(["", "## Network destinations", ""])
    if report["network_destinations"]:
        lines.extend(f"- `{item['scheme']}://{item['host']}`" for item in report["network_destinations"])
    else:
        lines.append("None extracted from inspected text.")
    lines.extend(["", "## Unresolved and excluded scope", ""])
    if report["unresolved"]:
        lines.extend(f"- `{item['path']}` — {item['reason']}" for item in report["unresolved"])
    else:
        lines.append("No unresolved scanner items.")
    if report.get("delta"):
        lines.extend(["", "## Delta from baseline", "", "```json", json.dumps(report["delta"], indent=2), "```"])
    lines.extend(["", "## Limitation", "", report["approval_statement"], ""])
    return "\n".join(lines)


def output_is_inside_candidate(candidate: Path, output: Path) -> bool:
    candidate = candidate.resolve()
    output = output.resolve()
    if candidate.is_dir():
        try:
            output.relative_to(candidate)
            return True
        except ValueError:
            return False
    return output == candidate


def parse_args() -> argparse.Namespace:
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
