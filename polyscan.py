#!/usr/bin/env python3
"""
POLY//SCAN — Universal Multi-Language Static Code Analyzer & Security Linter
=============================================================================
A complete, production-grade, zero-external-dependency CLI Static Application
Security Testing (SAST) engine supporting 11 programming languages:
Java, C, C++, Objective-C, C#, Python, JavaScript, PHP, Go, Rust, and Ruby.

Features:
- Recursive polyglot file discovery with .gitignore pattern matching and
  automatic vendor/build directory exclusion.
- Concurrent multi-threaded file analysis via concurrent.futures.ThreadPoolExecutor.
- Deterministic vulnerability rule matrix mapped to CWE & OWASP categories.
- Universal secret & credential detection with regex signatures and Shannon
  entropy calculation on variable string assignments.
- Context-aware comment stripping (single-line, block comments, docstrings/heredocs)
  and inline suppression directives (polyscan:ignore).
- Multi-line code snippet extraction (2 lines before and 2 lines after).
- Rich ANSI terminal output, structured JSON, and GitHub Code Scanning compatible
  SARIF 2.1.0 report generation.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Pattern, Sequence, Set, Tuple

__version__ = "2.4.0"
__tool_name__ = "POLY//SCAN"
__tool_uri__ = "https://polyscan.security.local/engine"


# =============================================================================
# 1. SEVERITY & CORE DATA MODELS
# =============================================================================


class Severity(IntEnum):
    """Normalized vulnerability severity levels with deterministic ordering."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, label: str) -> "Severity":
        normalized = label.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"Invalid severity '{label}'. Choose from: {valid}") from exc

    def to_sarif_level(self) -> str:
        """Map POLY//SCAN severity to SARIF 2.1.0 result level."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    def to_security_severity_score(self) -> str:
        """Map severity to GitHub Code Scanning CVSS-like numeric score string."""
        scores = {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "7.8",
            Severity.MEDIUM: "5.5",
            Severity.LOW: "3.2",
        }
        return scores[self]


@dataclass(frozen=True)
class CodeLineContext:
    """Single line of source code within a finding's context window."""

    line_number: int
    content: str
    is_target: bool = False


@dataclass(frozen=True)
class Rule:
    """Static analysis detection rule definition."""

    id: str
    name: str
    languages: Tuple[str, ...]
    severity: Severity
    cwe: str
    owasp: str
    description: str
    remediation: str
    pattern: Pattern[str]
    validator: Optional[Callable[[re.Match[str], str, str], bool]] = None
    multiline: bool = False


@dataclass
class Finding:
    """Concrete security finding discovered in a scanned file."""

    rule_id: str
    rule_name: str
    severity: str
    severity_rank: int
    cwe: str
    owasp: str
    language: str
    file_path: str
    line: int
    column: int
    end_column: int
    matched_text: str
    message: str
    remediation: str
    fingerprint: str
    context: List[CodeLineContext] = field(default_factory=list)
    entropy: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "language": self.language,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_column": self.end_column,
            "matched_text": self.matched_text,
            "message": self.message,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "context": [asdict(c) for c in self.context],
        }
        if self.entropy is not None:
            payload["entropy"] = round(self.entropy, 3)
        return payload


@dataclass
class FileScanOutcome:
    """Per-file scan telemetry and findings."""

    file_path: str
    language: str
    loc: int
    findings: List[Finding] = field(default_factory=list)
    suppressed_count: int = 0
    error: Optional[str] = None


@dataclass
class ScanSummary:
    """Aggregated telemetry for a complete POLY//SCAN execution."""

    root_path: str
    files_scanned: int
    loc_counted: int
    suppressed_findings: int
    elapsed_ms: float
    languages_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]
    findings: List[Finding]


# =============================================================================
# 2. POLYGLOT EXTENSION REGISTRY & DEFAULT IGNORE CONFIG
# =============================================================================

LANGUAGE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "java": (".java",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hxx"),
    "objc": (".m", ".mm"),
    "csharp": (".cs",),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "php": (".php", ".phtml"),
    "go": (".go",),
    "rust": (".rs",),
    "ruby": (".rb", ".rake"),
}

LANGUAGE_DISPLAY_NAMES: Dict[str, str] = {
    "java": "Java",
    "c": "C",
    "cpp": "C++",
    "objc": "Objective-C",
    "csharp": "C#",
    "python": "Python",
    "javascript": "JavaScript",
    "php": "PHP",
    "go": "Go",
    "rust": "Rust",
    "ruby": "Ruby",
}

LANGUAGE_ALIASES: Dict[str, str] = {
    "java": "java",
    "c": "c",
    "c++": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "objc": "objc",
    "objective-c": "objc",
    "objective_c": "objc",
    "obj-c": "objc",
    "cs": "csharp",
    "c#": "csharp",
    "csharp": "csharp",
    "dotnet": "csharp",
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "node": "javascript",
    "php": "php",
    "go": "go",
    "golang": "go",
    "rs": "rust",
    "rust": "rust",
    "rb": "ruby",
    "ruby": "ruby",
}

EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ext: lang for lang, exts in LANGUAGE_EXTENSIONS.items() for ext in exts
}

DEFAULT_SKIP_DIRS: Set[str] = {
    "node_modules",
    ".git",
    "vendor",
    "target",
    "dist",
    "build",
    "__pycache__",
    "venv",
    ".venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "bin",
    "obj",
    "out",
    "coverage",
}

INLINE_IGNORE_RE = re.compile(
    r"(?://|#|--|/\*+|\<!--)\s*polyscan\s*:\s*ignore(?:\[([a-zA-Z0-9_,\-\s]+)\])?",
    re.IGNORECASE,
)


# =============================================================================
# 3. GITIGNORE & WORKSPACE DISCOVERY ENGINE
# =============================================================================


@dataclass
class GitIgnoreRule:
    """Parsed representation of a single .gitignore pattern entry."""

    pattern: str
    base_dir: Path
    negated: bool = False
    dir_only: bool = False
    anchored: bool = False


class GitIgnoreMatcher:
    """Hierarchical .gitignore parser and matcher using only stdlib."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir.resolve()
        self.rules: List[GitIgnoreRule] = []
        self._loaded_dirs: Set[Path] = set()
        self.load_gitignore_in_dir(self.root_dir)

    def load_gitignore_in_dir(self, directory: Path) -> None:
        resolved = directory.resolve()
        if resolved in self._loaded_dirs:
            return
        self._loaded_dirs.add(resolved)
        gitignore_path = resolved / ".gitignore"
        if not gitignore_path.is_file():
            return
        try:
            lines = gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            negated = False
            if line.startswith("!"):
                negated = True
                line = line[1:].strip()
            if not line:
                continue
            dir_only = line.endswith("/")
            if dir_only:
                line = line.rstrip("/")
            anchored = line.startswith("/")
            if anchored:
                line = line.lstrip("/")
            if line:
                self.rules.append(
                    GitIgnoreRule(
                        pattern=line,
                        base_dir=resolved,
                        negated=negated,
                        dir_only=dir_only,
                        anchored=anchored,
                    )
                )

    def is_ignored(self, candidate: Path, is_dir: bool = False) -> bool:
        resolved = candidate.resolve()
        ignored = False
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            try:
                rel_path = resolved.relative_to(rule.base_dir).as_posix()
            except ValueError:
                continue

            name = resolved.name
            matched = False
            if rule.anchored or "/" in rule.pattern:
                if fnmatch.fnmatchcase(rel_path, rule.pattern) or fnmatch.fnmatchcase(
                    rel_path, f"{rule.pattern}/*"
                ):
                    matched = True
            else:
                if fnmatch.fnmatchcase(name, rule.pattern) or fnmatch.fnmatchcase(
                    rel_path, rule.pattern
                ):
                    matched = True
                else:
                    parts = rel_path.split("/")
                    if any(fnmatch.fnmatchcase(part, rule.pattern) for part in parts):
                        matched = True

            if matched:
                ignored = not rule.negated
        return ignored


class PolyglotFileDispatcher:
    """Discovers source files across all 11 supported languages."""

    def __init__(
        self,
        target_path: Path,
        allowed_languages: Optional[Set[str]] = None,
        skip_dirs: Optional[Set[str]] = None,
    ) -> None:
        self.target_path = target_path.resolve()
        self.allowed_languages = allowed_languages or set(LANGUAGE_EXTENSIONS.keys())
        self.skip_dirs = skip_dirs or DEFAULT_SKIP_DIRS

    def discover(self) -> List[Tuple[Path, str]]:
        """Return sorted list of (file_path, canonical_language) pairs."""
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        if self.target_path.is_file():
            lang = self._classify_file(self.target_path)
            if lang and lang in self.allowed_languages:
                return [(self.target_path, lang)]
            return []

        matcher = GitIgnoreMatcher(self.target_path)
        discovered: List[Tuple[Path, str]] = []

        for current_root, dirs, files in os.walk(self.target_path, topdown=True):
            root_path = Path(current_root)
            matcher.load_gitignore_in_dir(root_path)

            # Prune skipped and gitignored directories in-place
            filtered_dirs: List[str] = []
            for d in sorted(dirs):
                if d in self.skip_dirs or (d.startswith(".") and d != "."):
                    continue
                dir_path = root_path / d
                if matcher.is_ignored(dir_path, is_dir=True):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            for filename in sorted(files):
                file_path = root_path / filename
                lang = self._classify_file(file_path)
                if not lang or lang not in self.allowed_languages:
                    continue
                if matcher.is_ignored(file_path, is_dir=False):
                    continue
                discovered.append((file_path, lang))

        return discovered

    def _classify_file(self, file_path: Path) -> Optional[str]:
        suffix = file_path.suffix.lower()
        if suffix == ".h":
            return self._disambiguate_header(file_path)
        return EXTENSION_TO_LANGUAGE.get(suffix)

    @staticmethod
    def _disambiguate_header(header_path: Path) -> str:
        """Distinguish C headers from C++ or Objective-C headers when possible."""
        try:
            sample = header_path.read_text(encoding="utf-8", errors="ignore")[:4096]
        except OSError:
            return "c"
        if re.search(r"@interface\b|@protocol\b|#import\s+<Foundation/", sample):
            return "objc"
        if re.search(r"\b(?:namespace|template\s*<|class\s+\w+\s*[:{]|std::)", sample):
            return "cpp"
        return "c"


# =============================================================================
# 4. COMMENT STRIPPING, MULTILINE BLANKING & CONTEXT EXTRACTOR
# =============================================================================

# Languages using C-style // and /* ... */ comments
C_STYLE_COMMENT_LANGS: Set[str] = {
    "java",
    "c",
    "cpp",
    "objc",
    "csharp",
    "javascript",
    "php",
    "go",
    "rust",
}


def sanitize_code_preserving_layout(source: str, language: str) -> str:
    """
    Strip single-line comments, block comments, and raw heredocs / multiline docstrings
    while strictly preserving character offsets and newline positions so line & column
    calculations remain 100% accurate.

    Regular single-line string literals are preserved (to allow secret detection,
    SQL injection detection, and format string inspection inside code lines), whereas
    comments and standalone multiline docstrings/heredocs are replaced with spaces.
    """
    n = len(source)
    out = list(source)
    i = 0

    def blank_range(start: int, end: int) -> None:
        for idx in range(start, min(end, n)):
            if out[idx] != "\n":
                out[idx] = " "

    # Pre-pass for Ruby =begin ... =end block comments
    if language == "ruby":
        for match in re.finditer(r"(?m)^=begin\b.*?^=end\b[^\n]*", source, re.DOTALL):
            blank_range(match.start(), match.end())

    # Pre-pass for PHP/Ruby/C++/Rust/Go heredocs or raw multiline blocks
    if language in ("php", "ruby"):
        heredoc_re = re.compile(
            r"(?:<<<|<<[~-]?)\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?\s*\n.*?\n\s*\1\b",
            re.DOTALL,
        )
        for match in heredoc_re.finditer(source):
            blank_range(match.start(), match.end())

    while i < n:
        ch = out[i]
        nxt = out[i + 1] if i + 1 < n else ""
        nxt2 = out[i + 2] if i + 2 < n else ""

        # 1. Python triple-quoted multiline strings / docstrings
        if language == "python" and (
            (ch == '"' and nxt == '"' and nxt2 == '"')
            or (ch == "'" and nxt == "'" and nxt2 == "'")
        ):
            quote3 = ch * 3
            start = i
            i += 3
            while i < n and source[i : i + 3] != quote3:
                if source[i] == "\\":
                    i += 2
                else:
                    i += 1
            end = min(i + 3, n)
            blank_range(start, end)
            i = end
            continue

        # 2. Go & JavaScript backtick raw/template multiline strings
        if language in ("go", "javascript") and ch == "`":
            start = i
            i += 1
            while i < n and out[i] != "`":
                if language == "javascript" and out[i] == "\\":
                    i += 2
                else:
                    i += 1
            end = min(i + 1, n)
            if "\n" in source[start:end]:
                blank_range(start, end)
            i = end
            continue

        # 3. C-style block comments /* ... */
        if language in C_STYLE_COMMENT_LANGS and ch == "/" and nxt == "*":
            start = i
            i += 2
            while i < n and not (out[i] == "*" and (i + 1 < n and out[i + 1] == "/")):
                i += 1
            end = min(i + 2, n)
            blank_range(start, end)
            i = end
            continue

        # 4. C-style single-line comments // ...
        if language in C_STYLE_COMMENT_LANGS and ch == "/" and nxt == "/":
            start = i
            i += 2
            while i < n and out[i] != "\n":
                i += 1
            blank_range(start, i)
            continue

        # 5. Hash single-line comments # ... (Python, Ruby, PHP)
        if language in ("python", "ruby", "php") and ch == "#":
            if language == "php" and nxt == "[":
                i += 2
                continue
            start = i
            i += 1
            while i < n and out[i] != "\n":
                i += 1
            blank_range(start, i)
            continue

        # 6. Regular single-line string literals: advance past them so '//' or '#'
        # inside a string literal is never mistaken for the start of a comment.
        if ch in ('"', "'"):
            if language == "rust" and ch == "'":
                if i + 2 < n and out[i + 1] != "\\" and out[i + 2] == "'":
                    i += 3
                    continue
                i += 1
                continue

            quote_char = ch
            i += 1
            while i < n and out[i] != quote_char:
                if out[i] == "\\":
                    i += 2
                elif out[i] == "\n" and language not in ("php", "ruby"):
                    break
                else:
                    i += 1
            i += 1
            continue

        i += 1

    return "".join(out)


def is_line_suppressed(raw_line: str, rule_id: str) -> bool:
    """
    Check whether a source line has an inline suppression comment such as:
    `// polyscan:ignore`, `# polyscan:ignore`, `/* polyscan:ignore */`,
    or rule-scoped `// polyscan:ignore[PY-CWE78-001]`.
    """
    match = INLINE_IGNORE_RE.search(raw_line)
    if not match:
        return False
    scoped = match.group(1)
    if not scoped:
        return True
    allowed_ids = {token.strip().upper() for token in scoped.split(",") if token.strip()}
    return rule_id.upper() in allowed_ids or "ALL" in allowed_ids


def extract_line_context(
    lines: Sequence[str], target_line_1based: int, window: int = 2
) -> List[CodeLineContext]:
    """Extract `window` lines before and `window` lines after `target_line_1based`."""
    total = len(lines)
    start_line = max(1, target_line_1based - window)
    end_line = min(total, target_line_1based + window)
    snippet: List[CodeLineContext] = []
    for line_no in range(start_line, end_line + 1):
        snippet.append(
            CodeLineContext(
                line_number=line_no,
                content=lines[line_no - 1].rstrip("\r\n"),
                is_target=(line_no == target_line_1based),
            )
        )
    return snippet


# =============================================================================
# 5. SHANNON ENTROPY & UNIVERSAL SECRET ANALYZER
# =============================================================================

SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<var>
        (?:[a-z0-9_]*?(?:
            secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|
            auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret|
            encryption[_-]?key|signing[_-]?key|bearer|credentials?
        )[a-z0-9_]*)
    )\b
    \s*(?::=|=|=>|:)\s*
    (?P<quote>['"])(?P<val>[A-Za-z0-9+/=_\-\.~!@#$%^&*]{16,128})(?P=quote)
    """
)

FALSE_POSITIVE_SECRET_VALUES: Set[str] = {
    "changeme",
    "password",
    "your_api_key_here",
    "your-secret-key",
    "replace_with_secret",
    "example_secret_key",
    "dummy_secret_value",
    "0000000000000000",
    "1234567890abcdef",
    "abcdefghijklmnop",
    "application/json",
    "content-type",
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (bits per character) of a candidate string."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def is_likely_high_entropy_secret(candidate: str, min_entropy: float = 4.15) -> Tuple[bool, float]:
    """
    Evaluate whether a string literal assigned to a sensitive identifier exhibits
    random cryptographic secret characteristics rather than natural language,
    file paths, or template placeholders.
    """
    cleaned = candidate.strip()
    if len(cleaned) < 16:
        return False, 0.0
    lower = cleaned.lower()
    if any(fp in lower for fp in FALSE_POSITIVE_SECRET_VALUES):
        return False, 0.0
    if " " in cleaned or ("/" in cleaned and cleaned.startswith(("/", "./", "../", "http"))):
        return False, 0.0
    if cleaned.startswith(("${", "{{", "%(", "env(")):
        return False, 0.0
    has_upper = any(c.isupper() for c in cleaned)
    has_lower = any(c.islower() for c in cleaned)
    has_digit = any(c.isdigit() for c in cleaned)
    has_sym = any(not c.isalnum() for c in cleaned)
    if sum((has_upper, has_lower, has_digit, has_sym)) < 2:
        return False, 0.0
    entropy = calculate_shannon_entropy(cleaned)
    return entropy >= min_entropy, entropy


# =============================================================================
# 6. COMPREHENSIVE VULNERABILITY & BAD-PRACTICE RULE MATRIX
# =============================================================================

ALL_LANGUAGES: Tuple[str, ...] = tuple(LANGUAGE_EXTENSIONS.keys())


def _not_constant_format_string(match: re.Match[str], line: str, _full: str) -> bool:
    """Ensure the first format argument is a dynamic variable/expression, not a string literal."""
    arg = match.groupdict().get("arg", "").strip()
    if not arg:
        return True
    return not (arg.startswith('"') or arg.startswith("'") or arg.startswith('@"'))


def build_rule_registry() -> List[Rule]:
    """Build the complete deterministic CWE-mapped rule catalog across all 11 languages."""
    rules: List[Rule] = [
        # =====================================================================
        # UNIVERSAL SECRET & CREDENTIAL DETECTION (ALL 11 LANGUAGES)
        # =====================================================================
        Rule(
            id="UNI-SEC-001",
            name="Hardcoded Cryptographic Private Key",
            languages=ALL_LANGUAGES,
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            description="Hardcoded PEM/PKCS/OpenSSH private key block detected in source code.",
            remediation="Remove the private key immediately, rotate the compromised keypair, and load keys from a secure secret manager or environment variable at runtime.",
            pattern=re.compile(
                r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+|PGP\s+)?PRIVATE\s+KEY-----"
            ),
        ),
        Rule(
            id="UNI-SEC-002",
            name="Hardcoded AWS Access Key / Secret Key",
            languages=ALL_LANGUAGES,
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            description="Hardcoded AWS Access Key ID (AKIA/ASIA) or AWS Secret Access Key assignment discovered.",
            remediation="Revoke the AWS credential in IAM, switch to IAM roles / instance profiles, or inject credentials via environment variables.",
            pattern=re.compile(
                r"(?:\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b|(?:aws_secret_access_key|aws_secret_key)\s*(?::=|=|=>|:)\s*['\"][A-Za-z0-9/+=]{40}['\"])",
                re.IGNORECASE,
            ),
        ),
        Rule(
            id="UNI-SEC-003",
            name="Hardcoded Stripe / GitHub / Slack Live API Secret Token",
            languages=ALL_LANGUAGES,
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            description="Hardcoded live API secret key (Stripe sk_live/rk_live, GitHub ghp_/github_pat_, or Slack xox[baprs]-) detected.",
            remediation="Rotate the exposed API token immediately in the provider dashboard and retrieve secrets from a vault or environment configuration.",
            pattern=re.compile(
                r"\b(?:sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|gh[pousr]_[A-Za-z0-9_]{24,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z\-]{16,})\b"
            ),
        ),
        Rule(
            id="UNI-SEC-004",
            name="Hardcoded JSON Web Token (JWT)",
            languages=ALL_LANGUAGES,
            severity=Severity.HIGH,
            cwe="CWE-522",
            owasp="A07:2021-Identification and Authentication Failures",
            description="Hardcoded signed JSON Web Token (JWT) bearer token embedded directly in source code.",
            remediation="Do not store signed JWTs in source code. Mint short-lived tokens dynamically during tests or load credentials from secure environment variables.",
            pattern=re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
        ),

        # =====================================================================
        # C / C++ / OBJECTIVE-C MEMORY & FORMAT STRING RULES
        # =====================================================================
        Rule(
            id="CCPP-CWE120-001",
            name="Classic Buffer Overflow via Unbounded Memory/String Copy",
            languages=("c", "cpp", "objc"),
            severity=Severity.CRITICAL,
            cwe="CWE-120",
            owasp="A06:2021-Vulnerable and Outdated Components",
            description="Use of inherently unsafe, unbounded string/buffer function (gets, strcpy, strcat, sprintf, vsprintf) without destination size verification.",
            remediation="Replace with bounded alternatives such as fgets(), strncpy()/strlcpy(), strncat()/strlcat(), or snprintf()/vsnprintf() with explicit buffer length limits.",
            pattern=re.compile(
                r"\b(?:gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|swprintf)\s*\("
            ),
        ),
        Rule(
            id="CCPP-CWE134-002",
            name="Uncontrolled Format String Vulnerability",
            languages=("c", "cpp", "objc"),
            severity=Severity.HIGH,
            cwe="CWE-134",
            owasp="A03:2021-Injection",
            description="Dynamic variable passed directly as the format string argument to printf/syslog/NSLog family function, allowing arbitrary memory read/write via %n/%x specifiers.",
            remediation="Always pass a constant format string literal as the first format parameter (e.g., printf(\"%s\", user_input) or NSLog(@\"%@\", userInput)).",
            pattern=re.compile(
                r"\b(?:printf|vprintf|syslog|NSLog)\s*\(\s*(?P<arg>(?![\"@'][%A-Za-z0-9_\s])[A-Za-z_][A-Za-z0-9_.\->]*)\s*\)"
            ),
            validator=_not_constant_format_string,
        ),
        Rule(
            id="CCPP-CWE134-003",
            name="Uncontrolled Format String in Stream/Buffer Function",
            languages=("c", "cpp", "objc"),
            severity=Severity.HIGH,
            cwe="CWE-134",
            owasp="A03:2021-Injection",
            description="Dynamic variable passed as format specifier to fprintf/snprintf/sprintf instead of a static format literal.",
            remediation="Provide a static format string literal (e.g., fprintf(stderr, \"%s\", msg) or snprintf(buf, sizeof(buf), \"%s\", msg)).",
            pattern=re.compile(
                r"\b(?:fprintf|vfprintf|sprintf|vsprintf)\s*\(\s*[^,]+,\s*(?P<arg>(?![\"'])[A-Za-z_][A-Za-z0-9_.\->]*)\s*\)"
            ),
            validator=_not_constant_format_string,
        ),
        Rule(
            id="CCPP-CWE416-004",
            name="Use-After-Free / Double-Free Memory Hazard",
            languages=("c", "cpp", "objc"),
            severity=Severity.CRITICAL,
            cwe="CWE-416",
            owasp="A04:2021-Insecure Design",
            description="Pointer is dereferenced, accessed, or freed a second time after being passed to free() or delete without re-assignment or nullification.",
            remediation="Set pointers to NULL/nullptr immediately after free()/delete, or use RAII smart pointers (std::unique_ptr, std::shared_ptr) and ARC in Objective-C.",
            pattern=re.compile(
                r"(?:\bfree\s*\(\s*(?P<ptr>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;(?:(?!(?P=ptr)\s*=)[^{}]){0,220}?(?:\bfree\s*\(\s*(?P=ptr)\s*\)|(?P=ptr)\s*(?:->|\[)|\*(?P=ptr)\b)|\bdelete(?:\s*\[\s*\])?\s+(?P<cppptr>[A-Za-z_][A-Za-z0-9_]*)\s*;(?:(?!(?P=cppptr)\s*=)[^{}]){0,220}?(?:\bdelete(?:\s*\[\s*\])?\s+(?P=cppptr)\b|(?P=cppptr)\s*(?:->|\[)|\*(?P=cppptr)\b))",
                re.DOTALL,
            ),
            multiline=True,
        ),
        Rule(
            id="OBJC-CWE295-005",
            name="Objective-C Improper TLS Certificate Validation Override",
            languages=("objc",),
            severity=Severity.HIGH,
            cwe="CWE-295",
            owasp="A02:2021-Cryptographic Failures",
            description="TLS certificate validation disabled via allowsInvalidSSLCertificates or setAllowsAnyHTTPSCertificate, exposing traffic to MITM interception.",
            remediation="Enforce strict X.509 certificate chain validation and certificate pinning via NSURLSessionDelegate in production builds.",
            pattern=re.compile(
                r"(?:allowsInvalidSSLCertificates\s*=\s*(?:YES|true)|setAllowsAnyHTTPSCertificate\s*:\s*(?:YES|true)|kCFStreamSSLValidatesCertificateChain\s*:\s*@(?:\(NO\)|NO|false))"
            ),
        ),

        # =====================================================================
        # JAVA & C# INJECTION, DESERIALIZATION & XSS RULES
        # =====================================================================
        Rule(
            id="JVMCS-CWE89-001",
            name="SQL Injection via String Concatenation in Query Execution",
            languages=("java", "csharp"),
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            description="Dynamic string concatenation or interpolation inside Statement.executeQuery/executeUpdate, SqlCommand, or Entity Framework FromSqlRaw/ExecuteSqlRaw.",
            remediation="Use parameterized PreparedStatement (Java) or SqlCommand with SqlParameter / FromSqlInterpolated (C#) instead of string concatenation.",
            pattern=re.compile(
                r"(?:\b(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand)\s*\(\s*(?:\$\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\{[^\}]+\}|\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^\"]*\"\s*\+|[^\)\n]*\+\s*[A-Za-z_][A-Za-z0-9_.]*)|\bnew\s+(?:SqlCommand|SqliteCommand|NpgsqlCommand|MySqlCommand|OracleCommand)\s*\(\s*(?:\$\"[^\"]*\{|\"[^\"]*\"\s*\+))",
                re.IGNORECASE,
            ),
        ),
        Rule(
            id="JVMCS-CWE502-002",
            name="Insecure Deserialization of Untrusted Byte Stream",
            languages=("java", "csharp"),
            severity=Severity.CRITICAL,
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            description="Untrusted object deserialization via ObjectInputStream.readObject(), XMLDecoder.readObject(), BinaryFormatter.Deserialize(), NetDataContractSerializer, or LosFormatter.",
            remediation="Avoid native binary deserialization. Migrate to safe structured formats (JSON/Protobuf) or enforce strict ObjectInputFilter / SerializationBinder allowlists.",
            pattern=re.compile(
                r"(?:\b(?:ObjectInputStream|XMLDecoder|BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter|ObjectStateFormatter)\b[^\n;]{0,120}?\.(?:readObject|Deserialize)\s*\(|\b(?:readObject)\s*\(\s*\)|\.[Dd]eserialize\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*\)|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays))"
            ),
        ),
        Rule(
            id="JVMCS-CWE79-003",
            name="Reflected Cross-Site Scripting (XSS) in Unescaped Response Writer",
            languages=("java", "csharp"),
            severity=Severity.HIGH,
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            description="Unescaped request data or dynamic variable written directly to HttpServletResponse.getWriter() or ASP.NET Response.Write / Html.Raw.",
            remediation="HTML-encode all dynamic output using OWASP Java Encoder, WebUtility.HtmlEncode(), or Razor automatic contextual encoding.",
            pattern=re.compile(
                r"(?:(?:response\.getWriter\(\)|out)\.(?:print|println|write|format)\s*\([^\)\n]*(?:request\.getParameter|getQueryString|getHeader|\+\s*[A-Za-z_][A-Za-z0-9_]*)|(?:\bResponse\.Write(?:Async)?|Html\.Raw)\s*\(\s*(?:Request\[|Request\.(?:QueryString|Form|Params|Headers)|[^\)\n]*\+\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_.]*\)))"
            ),
        ),
        Rule(
            id="JVMCS-CWE611-004",
            name="XML External Entity (XXE) Processing Enabled",
            languages=("java", "csharp"),
            severity=Severity.HIGH,
            cwe="CWE-611",
            owasp="A05:2021-Security Misconfiguration",
            description="XML parser instantiated or configured with external DTD/entity resolution enabled (DocumentBuilderFactory/SAXParserFactory/XmlReaderSettings DtdProcessing.Parse).",
            remediation="Disable DOCTYPE declarations (disallow-doctype-decl) in Java XML factories and set DtdProcessing = DtdProcessing.Prohibit with XmlResolver = null in .NET.",
            pattern=re.compile(
                r"(?:DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlUrlResolver\s*\(\s*\)|setExpandEntityReferences\s*\(\s*true\s*\))"
            ),
        ),

        # =====================================================================
        # PYTHON / RUBY / PHP COMMAND INJECTION, CODE EXEC & XXE RULES
        # =====================================================================
        Rule(
            id="PRP-CWE78-001",
            name="OS Command Injection via Shell Execution",
            languages=("python", "ruby", "php"),
            severity=Severity.CRITICAL,
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            description="Execution of OS shell commands via os.system/popen, subprocess with shell=True, PHP system/exec/passthru/shell_exec, or Ruby kernel system/Open3 with dynamic input.",
            remediation="Invoke external binaries using argument arrays without invoking a shell (e.g., subprocess.run([cmd, arg], shell=False) in Python) and validate arguments against strict allowlists.",
            pattern=re.compile(
                r"(?:\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^\)\n]*\bshell\s*=\s*True|\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s*\(|\b(?:system|exec)\s*\(\s*(?:\$[A-Za-z_]|f['\"]|['\"][^'\"]*#\{|[A-Za-z_][A-Za-z0-9_]*\s*\+)|\bOpen3\.(?:capture2|capture2e|capture3|popen3)\s*\(\s*(?:['\"][^'\"]*#\{|[A-Za-z_]))"
            ),
        ),
        Rule(
            id="PRP-CWE94-002",
            name="Arbitrary Dynamic Code Execution (eval / exec / create_function)",
            languages=("python", "ruby", "php"),
            severity=Severity.CRITICAL,
            cwe="CWE-94",
            owasp="A03:2021-Injection",
            description="Dynamic evaluation of code strings using eval(), exec(), create_function(), assert() with string, or Ruby binding/instance/class_eval.",
            remediation="Eliminate dynamic code evaluation. Use ast.literal_eval() in Python or safe JSON/data parsers and explicit dispatch tables.",
            pattern=re.compile(
                r"(?:\b(?:eval|create_function)\s*\(|\b(?:instance_eval|class_eval|module_eval|Kernel\.eval)\b|\bexec\s*\(\s*(?:f['\"]|\$[A-Za-z_]|[A-Za-z_][A-Za-z0-9_.]*\s*[\),+])|\bpreg_replace\s*\(\s*['\"][^'\"]*/[imsxADSUXJu]*e[imsxADSUXJu]*['\"])"
            ),
        ),
        Rule(
            id="PRP-CWE611-003",
            name="XML External Entity (XXE) Injection via Unconfigured XML Parser",
            languages=("python", "ruby", "php"),
            severity=Severity.HIGH,
            cwe="CWE-611",
            owasp="A05:2021-Security Misconfiguration",
            description="XML parser configured to resolve external entities (lxml resolve_entities=True, PHP LIBXML_NOENT/LIBXML_DTDLOAD, or Ruby Nokogiri DTDLOAD/NOENT).",
            remediation="Use defusedxml in Python, avoid LIBXML_NOENT/LIBXML_DTDLOAD in PHP, and disable Nokogiri::XML::ParseOptions::NOENT / DTDLOAD in Ruby.",
            pattern=re.compile(
                r"(?:\bresolve_entities\s*=\s*True\b|\bXMLParser\s*\([^\)\n]*\bdtd_validation\s*=\s*True|\b(?:LIBXML_NOENT|LIBXML_DTDLOAD)\b|\bNokogiri::XML::ParseOptions::(?:NOENT|DTDLOAD)\b|\bxml\.sax\.make_parser\s*\()"
            ),
        ),
        Rule(
            id="PRP-CWE502-004",
            name="Unsafe Object Deserialization (pickle / yaml.load / Marshal / unserialize)",
            languages=("python", "ruby", "php"),
            severity=Severity.CRITICAL,
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            description="Deserialization of untrusted payloads via Python pickle.loads/yaml.unsafe_load, Ruby Marshal.load/YAML.load, or PHP unserialize().",
            remediation="Use safe data serialization formats like JSON, yaml.safe_load() in Python, YAML.safe_load in Ruby, or json_decode() in PHP.",
            pattern=re.compile(
                r"(?:\b(?:pickle|cPickle|dill|shelve)\.(?:loads?|Unpickler)\s*\(|\byaml\.(?:unsafe_load|full_load)\s*\(|\byaml\.load\s*\([^,\)\n]+\)|\bMarshal\.(?:load|restore)\s*\(|\bunserialize\s*\(\s*\$)"
            ),
        ),

        # =====================================================================
        # GO SECURITY RULES
        # =====================================================================
        Rule(
            id="GO-CWE252-001",
            name="Go Unhandled Error on Security-Critical Operation",
            languages=("go",),
            severity=Severity.HIGH,
            cwe="CWE-252",
            owasp="A04:2021-Insecure Design",
            description="Ignored error return value (assigned to blank identifier `_`) on a security-critical cryptographic, authentication, permission, or I/O operation.",
            remediation="Explicitly capture and handle the returned `err` value instead of discarding it with `_`, failing closed when security operations error.",
            pattern=re.compile(
                r"(?:\b[A-Za-z0-9_]+\s*,\s*_\s*:?=\s*(?:rand\.Read|bcrypt\.GenerateFromPassword|cipher\.[A-Za-z0-9_]+|rsa\.[A-Za-z0-9_]+|ecdsa\.[A-Za-z0-9_]+|jwt\.Parse[A-Za-z0-9_]*|os\.(?:Chmod|Chown|Setenv)|tls\.[A-Za-z0-9_]+)\s*\(|\b_\s*=\s*(?:rand\.Read|bcrypt\.CompareHashAndPassword|os\.(?:Chmod|Chown|RemoveAll)|http\.ListenAndServe(?:TLS)?|db\.Exec)\s*\()"
            ),
        ),
        Rule(
            id="GO-CWE242-002",
            name="Go Memory Safety Bypass via unsafe.Pointer / uintptr Conversion",
            languages=("go",),
            severity=Severity.HIGH,
            cwe="CWE-242",
            owasp="A04:2021-Insecure Design",
            description="Use of `unsafe.Pointer`, `unsafe.Slice`, or `uintptr` pointer arithmetic bypasses Go's type safety and garbage collector guarantees.",
            remediation="Refactor to use safe typed slices, `encoding/binary`, or standard reflection without `unsafe.Pointer` casts.",
            pattern=re.compile(r"\bunsafe\.(?:Pointer|Slice|StringData|SliceData)\s*\("),
        ),
        Rule(
            id="GO-CWE89-003",
            name="Go SQL Injection via Dynamic Query Formatting in database/sql",
            languages=("go",),
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            description="Dynamic SQL query constructed with fmt.Sprintf or string concatenation passed directly to db.Query / db.QueryRow / db.Exec.",
            remediation="Use positional parameter placeholders (`?` or `$1`) with `db.Query(ctx, \"SELECT ... WHERE id = $1\", id)`.",
            pattern=re.compile(
                r"\b(?:db|tx|conn|stmt)\.(?:Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)\s*\(\s*(?:fmt\.Sprintf\s*\(|[^\)\n]*\+\s*[A-Za-z_][A-Za-z0-9_.]*)"
            ),
        ),

        # =====================================================================
        # RUST SECURITY RULES
        # =====================================================================
        Rule(
            id="RS-CWE242-001",
            name="Rust Unsafe Block Bypassing Borrow Checker Guarantees",
            languages=("rust",),
            severity=Severity.MEDIUM,
            cwe="CWE-242",
            owasp="A04:2021-Insecure Design",
            description="Usage of `unsafe { ... }` block or `unsafe fn` disables Rust's compile-time borrow, lifetime, and memory aliasing checks.",
            remediation="Minimize `unsafe` blocks, encapsulate FFI invariants behind safe abstractions, and document safety invariants with `// SAFETY:` comments.",
            pattern=re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)"),
        ),
        Rule(
            id="RS-CWE704-002",
            name="Rust Arbitrary Type Reinterpretation via mem::transmute",
            languages=("rust",),
            severity=Severity.CRITICAL,
            cwe="CWE-704",
            owasp="A04:2021-Insecure Design",
            description="Usage of `std::mem::transmute` or `core::mem::transmute` reinterprets raw bits across types, easily causing undefined behavior and memory corruption.",
            remediation="Use safe type conversions (`From`/`TryFrom`, `as` casts on primitives, `bytemuck`, or `to_ne_bytes`/`from_ne_bytes`) instead of `transmute`.",
            pattern=re.compile(
                r"\b(?:std::mem::|core::mem::|mem::)?transmute(?:_copy)?\s*(?:::<[^>]+>)?\s*\("
            ),
        ),
        Rule(
            id="RS-CWE248-003",
            name="Rust Panic / DoS Risk via .unwrap() on Fallible Security Operation",
            languages=("rust",),
            severity=Severity.HIGH,
            cwe="CWE-248",
            owasp="A05:2021-Security Misconfiguration",
            description="Calling `.unwrap()` on fallible I/O, network, mutex lock, cryptographic, or user-input parsing operations can trigger an unrecoverable thread panic (DoS).",
            remediation="Propagate errors using the `?` operator, handle `Result`/`Option` branches explicitly with `match` or `if let`, or return a domain error.",
            pattern=re.compile(
                r"(?:\b(?:File::open|File::create|TcpStream::connect|TcpListener::bind|Command::new|serde_json::from_str|serde_json::from_slice|str::from_utf8|CString::new|Mutex::lock|RwLock::read|RwLock::write|env::var|HeaderValue::from_str)\b[^\n;]{0,100}?\.unwrap\s*\(\s*\)|\.(?:lock|read|write|parse|from_str|decrypt|verify)\s*\([^\)\n]*\)\.unwrap\s*\(\s*\))"
            ),
        ),

        # =====================================================================
        # JAVASCRIPT DOM XSS & CODE EXECUTION RULES
        # =====================================================================
        Rule(
            id="JS-CWE79-001",
            name="DOM-Based Cross-Site Scripting (XSS) via innerHTML / document.write",
            languages=("javascript",),
            severity=Severity.HIGH,
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            description="Assignment of unescaped content to `.innerHTML`, `.outerHTML`, `insertAdjacentHTML()`, `document.write()`, or React `dangerouslySetInnerHTML`.",
            remediation="Use `.textContent` or `.innerText` for plain text, or sanitize HTML payloads with DOMPurify before inserting into the DOM.",
            pattern=re.compile(
                r"(?:\.(?:innerHTML|outerHTML)\s*\+?=\s*(?![\s]*['\"]\s*['\"])|\bdocument\.write(?:ln)?\s*\(|\binsertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\s*=\s*\{)"
            ),
        ),
        Rule(
            id="JS-CWE95-002",
            name="Dynamic JavaScript Code Execution via eval / Function / Timer String",
            languages=("javascript",),
            severity=Severity.CRITICAL,
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            description="Execution of arbitrary JavaScript code via `eval()`, `new Function()`, or passing a string argument to `setTimeout()` / `setInterval()`.",
            remediation="Replace `eval()` with `JSON.parse()` for data parsing, and pass function references instead of strings to `setTimeout`/`setInterval`.",
            pattern=re.compile(
                r"(?:\beval\s*\(|\bnew\s+Function\s*\(|\b(?:setTimeout|setInterval)\s*\(\s*['\"`])"
            ),
        ),
        Rule(
            id="JS-CWE1321-003",
            name="JavaScript Prototype Pollution via Unsafe Recursive Merge / __proto__",
            languages=("javascript",),
            severity=Severity.HIGH,
            cwe="CWE-1321",
            owasp="A03:2021-Injection",
            description="Direct mutation or unvalidated dynamic key assignment touching `__proto__`, `constructor.prototype`, or `Object.setPrototypeOf`.",
            remediation="Freeze `Object.prototype`, use `Object.create(null)` or `Map` for untrusted dictionaries, and reject keys `__proto__`, `constructor`, and `prototype`.",
            pattern=re.compile(
                r"(?:__proto__\s*(?:\[|\.|=)|constructor\.prototype\s*(?:\[|\.|=)|\bObject\.setPrototypeOf\s*\()"
            ),
        ),
    ]
    return rules


# =============================================================================
# 7. CORE STATIC ANALYSIS ENGINE
# =============================================================================


class PolyScanEngine:
    """Executes deterministic static analysis rules and entropy checks across files."""

    def __init__(
        self,
        min_severity: Severity = Severity.LOW,
        allowed_languages: Optional[Set[str]] = None,
        max_workers: Optional[int] = None,
    ) -> None:
        self.min_severity = min_severity
        self.allowed_languages = allowed_languages or set(LANGUAGE_EXTENSIONS.keys())
        self.max_workers = max_workers or min(32, (os.cpu_count() or 4) + 4)
        self.all_rules = build_rule_registry()
        self.rules_by_lang: Dict[str, List[Rule]] = {lang: [] for lang in LANGUAGE_EXTENSIONS}
        for rule in self.all_rules:
            if rule.severity < self.min_severity:
                continue
            for lang in rule.languages:
                if lang in self.rules_by_lang:
                    self.rules_by_lang[lang].append(rule)

    def scan_target(self, target_path: Path) -> ScanSummary:
        """Run full workspace discovery and concurrent analysis."""
        start_ns = time.perf_counter_ns()
        dispatcher = PolyglotFileDispatcher(
            target_path=target_path, allowed_languages=self.allowed_languages
        )
        discovered_files = dispatcher.discover()

        outcomes: List[FileScanOutcome] = []
        if discovered_files:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_map = {
                    executor.submit(self.scan_single_file, file_path, lang, target_path): (
                        file_path,
                        lang,
                    )
                    for file_path, lang in discovered_files
                }
                for future in as_completed(future_map):
                    outcomes.append(future.result())

        outcomes.sort(key=lambda o: o.file_path)

        total_loc = 0
        total_suppressed = 0
        lang_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {s.name: 0 for s in Severity}
        all_findings: List[Finding] = []

        for outcome in outcomes:
            total_loc += outcome.loc
            total_suppressed += outcome.suppressed_count
            lang_counts[outcome.language] = lang_counts.get(outcome.language, 0) + 1
            for finding in outcome.findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
                all_findings.append(finding)

        all_findings.sort(
            key=lambda f: (-f.severity_rank, f.file_path, f.line, f.column, f.rule_id)
        )

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        return ScanSummary(
            root_path=str(target_path.resolve()),
            files_scanned=len(outcomes),
            loc_counted=total_loc,
            suppressed_findings=total_suppressed,
            elapsed_ms=elapsed_ms,
            languages_breakdown=lang_counts,
            severity_breakdown=severity_counts,
            findings=all_findings,
        )

    def scan_single_file(
        self, file_path: Path, language: str, root_path: Path
    ) -> FileScanOutcome:
        """Scan a single source file using sanitized layout-preserving text."""
        try:
            raw_source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return FileScanOutcome(
                file_path=str(file_path),
                language=language,
                loc=0,
                error=str(exc),
            )

        raw_lines = raw_source.splitlines()
        loc = sum(1 for line in raw_lines if line.strip())

        try:
            if root_path.is_dir():
                display_path = file_path.resolve().relative_to(root_path.resolve()).as_posix()
            else:
                display_path = file_path.name
        except ValueError:
            display_path = file_path.as_posix()

        sanitized = sanitize_code_preserving_layout(raw_source, language)
        sanitized_lines = sanitized.splitlines()

        line_starts: List[int] = [0]
        for idx, ch in enumerate(sanitized):
            if ch == "\n":
                line_starts.append(idx + 1)

        findings: List[Finding] = []
        seen_keys: Set[Tuple[str, int, int]] = set()
        suppressed_count = 0

        applicable_rules = self.rules_by_lang.get(language, [])

        for rule in applicable_rules:
            if rule.multiline:
                for match in rule.pattern.finditer(sanitized):
                    line_no, col_no = self._offset_to_line_col(line_starts, match.start())
                    end_line_no, _ = self._offset_to_line_col(line_starts, match.end())
                    # Check inline suppression across any line spanned by the multiline match
                    if any(
                        1 <= ln <= len(raw_lines) and is_line_suppressed(raw_lines[ln - 1], rule.id)
                        for ln in range(line_no, end_line_no + 1)
                    ):
                        suppressed_count += 1
                        continue
                    raw_line = raw_lines[line_no - 1] if 1 <= line_no <= len(raw_lines) else ""
                    if rule.validator and not rule.validator(match, raw_line, sanitized):
                        continue
                    dedup_key = (rule.id, line_no, col_no)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    matched_snippet = " ".join(match.group(0).split())
                    if len(matched_snippet) > 140:
                        matched_snippet = matched_snippet[:137] + "..."
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            language=language,
                            file_path=display_path,
                            line_no=line_no,
                            col_no=col_no,
                            end_col=col_no + len(matched_snippet),
                            matched_text=matched_snippet,
                            raw_lines=raw_lines,
                        )
                    )
            else:
                for line_idx, san_line in enumerate(sanitized_lines):
                    if not san_line.strip():
                        continue
                    line_no = line_idx + 1
                    raw_line = raw_lines[line_idx] if line_idx < len(raw_lines) else san_line
                    for match in rule.pattern.finditer(san_line):
                        if is_line_suppressed(raw_line, rule.id):
                            suppressed_count += 1
                            continue
                        if rule.validator and not rule.validator(match, san_line, sanitized):
                            continue
                        col_no = match.start() + 1
                        end_col = match.end() + 1
                        dedup_key = (rule.id, line_no, col_no)
                        if dedup_key in seen_keys:
                            continue
                        seen_keys.add(dedup_key)
                        findings.append(
                            self._create_finding(
                                rule=rule,
                                language=language,
                                file_path=display_path,
                                line_no=line_no,
                                col_no=col_no,
                                end_col=end_col,
                                matched_text=match.group(0).strip(),
                                raw_lines=raw_lines,
                            )
                        )

        # Universal Shannon Entropy Secret Assignment Pass (All 11 Languages)
        if Severity.HIGH >= self.min_severity:
            for line_idx, san_line in enumerate(sanitized_lines):
                if not san_line.strip():
                    continue
                line_no = line_idx + 1
                raw_line = raw_lines[line_idx] if line_idx < len(raw_lines) else san_line
                if any(
                    f.line == line_no and f.rule_id.startswith("UNI-SEC-") for f in findings
                ):
                    continue
                for match in SECRET_ASSIGNMENT_RE.finditer(san_line):
                    if is_line_suppressed(raw_line, "UNI-SEC-005"):
                        suppressed_count += 1
                        continue
                    secret_val = match.group("val")
                    var_name = match.group("var")
                    is_secret, entropy_val = is_likely_high_entropy_secret(secret_val)
                    if not is_secret:
                        continue
                    col_no = match.start() + 1
                    end_col = match.end() + 1
                    dedup_key = ("UNI-SEC-005", line_no, col_no)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    entropy_rule = Rule(
                        id="UNI-SEC-005",
                        name="High-Entropy Hardcoded Secret Assignment",
                        languages=ALL_LANGUAGES,
                        severity=Severity.HIGH,
                        cwe="CWE-798",
                        owasp="A07:2021-Identification and Authentication Failures",
                        description=(
                            f"Variable '{var_name}' is assigned a high-entropy string literal "
                            f"(Shannon entropy: {entropy_val:.2f} bits/char), indicating a hardcoded secret or API key."
                        ),
                        remediation="Move secrets out of source code into environment variables or a dedicated secret management service.",
                        pattern=SECRET_ASSIGNMENT_RE,
                    )
                    findings.append(
                        self._create_finding(
                            rule=entropy_rule,
                            language=language,
                            file_path=display_path,
                            line_no=line_no,
                            col_no=col_no,
                            end_col=end_col,
                            matched_text=match.group(0).strip(),
                            raw_lines=raw_lines,
                            entropy=entropy_val,
                        )
                    )

        return FileScanOutcome(
            file_path=display_path,
            language=language,
            loc=loc,
            findings=findings,
            suppressed_count=suppressed_count,
        )

    @staticmethod
    def _offset_to_line_col(line_starts: Sequence[int], offset: int) -> Tuple[int, int]:
        """Convert 0-based character offset to 1-based (line, column)."""
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid - 1
        line_idx = max(0, hi)
        col = (offset - line_starts[line_idx]) + 1
        return line_idx + 1, col

    @staticmethod
    def _create_finding(
        rule: Rule,
        language: str,
        file_path: str,
        line_no: int,
        col_no: int,
        end_col: int,
        matched_text: str,
        raw_lines: Sequence[str],
        entropy: Optional[float] = None,
    ) -> Finding:
        fingerprint_seed = f"{rule.id}:{file_path}:{line_no}:{col_no}:{matched_text}"
        fingerprint = hashlib.sha256(fingerprint_seed.encode("utf-8")).hexdigest()[:24]
        context = extract_line_context(raw_lines, line_no, window=2)
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity.name,
            severity_rank=int(rule.severity),
            cwe=rule.cwe,
            owasp=rule.owasp,
            language=language,
            file_path=file_path,
            line=line_no,
            column=col_no,
            end_column=max(col_no + 1, end_col),
            matched_text=matched_text,
            message=rule.description,
            remediation=rule.remediation,
            fingerprint=fingerprint,
            context=context,
            entropy=entropy,
        )


# =============================================================================
# 8. REPORTING FORMATTERS: ANSI TERMINAL, JSON, AND SARIF 2.1.0
# =============================================================================


class AnsiPalette:
    """ANSI terminal escape sequences with automatic non-TTY fallback."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def _code(self, seq: str) -> str:
        return seq if self.enabled else ""

    @property
    def reset(self) -> str:
        return self._code("\033[0m")

    @property
    def bold(self) -> str:
        return self._code("\033[1m")

    @property
    def dim(self) -> str:
        return self._code("\033[2m")

    @property
    def cyan(self) -> str:
        return self._code("\033[36m")

    @property
    def blue(self) -> str:
        return self._code("\033[34m")

    @property
    def green(self) -> str:
        return self._code("\033[32m")

    @property
    def yellow(self) -> str:
        return self._code("\033[33m")

    @property
    def red(self) -> str:
        return self._code("\033[31m")

    @property
    def magenta(self) -> str:
        return self._code("\033[35m")

    @property
    def bg_red(self) -> str:
        return self._code("\033[41;97;1m")

    def severity_badge(self, severity_name: str) -> str:
        sev = severity_name.upper()
        if sev == "CRITICAL":
            return f"{self.bg_red} CRITICAL {self.reset}"
        if sev == "HIGH":
            return f"{self.bold}{self.red}[HIGH]{self.reset}"
        if sev == "MEDIUM":
            return f"{self.bold}{self.yellow}[MEDIUM]{self.reset}"
        return f"{self.bold}{self.cyan}[LOW]{self.reset}"


def format_terminal_report(summary: ScanSummary, use_color: bool = True) -> str:
    """Render human-readable terminal report with ANSI colors, context snippets, and summary box."""
    c = AnsiPalette(enabled=use_color)
    out: List[str] = []

    banner = (
        f"{c.bold}{c.cyan}╔══════════════════════════════════════════════════════════════════════════════╗{c.reset}\n"
        f"{c.bold}{c.cyan}║{c.reset}  {c.bold}POLY//SCAN v{__version__}{c.reset} — Universal Multi-Language Static Code Analyzer (SAST)   {c.bold}{c.cyan}║{c.reset}\n"
        f"{c.bold}{c.cyan}╚══════════════════════════════════════════════════════════════════════════════╝{c.reset}"
    )
    out.append(banner)
    out.append(f"{c.dim}Target Workspace:{c.reset} {summary.root_path}\n")

    if not summary.findings:
        out.append(
            f"{c.bold}{c.green}✔ No security findings detected matching current filter criteria.{c.reset}\n"
        )
    else:
        for idx, f in enumerate(summary.findings, start=1):
            badge = c.severity_badge(f.severity)
            lang_label = LANGUAGE_DISPLAY_NAMES.get(f.language, f.language)
            out.append(
                f"{badge} {c.bold}{f.rule_id}{c.reset}: {c.bold}{f.rule_name}{c.reset} "
                f"{c.dim}({f.cwe} | {f.owasp} | {lang_label}){c.reset}"
            )
            out.append(
                f"  {c.cyan}➜{c.reset} {c.bold}{f.file_path}:{f.line}:{f.column}{c.reset} "
                f"{c.dim}[fingerprint: {f.fingerprint[:12]}]{c.reset}"
            )
            out.append(f"  {c.dim}│{c.reset}")
            for ctx in f.context:
                if ctx.is_target:
                    marker = f"{c.bold}{c.red}>{c.reset}"
                    line_num_str = f"{c.bold}{c.red}{ctx.line_number:4d}{c.reset}"
                    code_str = f"{c.bold}{ctx.content}{c.reset}"
                else:
                    marker = " "
                    line_num_str = f"{c.dim}{ctx.line_number:4d}{c.reset}"
                    code_str = f"{c.dim}{ctx.content}{c.reset}"
                out.append(f"  {marker} {line_num_str} {c.dim}│{c.reset} {code_str}")
            out.append(f"  {c.dim}│{c.reset}")
            out.append(f"  {c.yellow}Issue:{c.reset}       {f.message}")
            out.append(f"  {c.green}Remediation:{c.reset} {f.remediation}")
            if idx < len(summary.findings):
                out.append(f"{c.dim}{'─' * 80}{c.reset}")
        out.append("")

    crit_cnt = summary.severity_breakdown.get("CRITICAL", 0)
    high_cnt = summary.severity_breakdown.get("HIGH", 0)
    med_cnt = summary.severity_breakdown.get("MEDIUM", 0)
    low_cnt = summary.severity_breakdown.get("LOW", 0)
    total_findings = len(summary.findings)

    langs_summary = (
        ", ".join(
            f"{LANGUAGE_DISPLAY_NAMES.get(k, k)} ({v})"
            for k, v in sorted(summary.languages_breakdown.items())
        )
        or "None"
    )

    out.append(
        f"{c.bold}{c.cyan}┌──────────────────────────────────────────────────────────────────────────────┐{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset} {c.bold}POLY//SCAN EXECUTION SUMMARY{c.reset}                                                 {c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}├──────────────────────────────────────────────────────────────────────────────┤{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset}  Files Scanned      : {c.bold}{summary.files_scanned:<12d}{c.reset} Lines of Code (LOC) : {c.bold}{summary.loc_counted:<18d}{c.reset}{c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset}  Total Findings     : {c.bold}{total_findings:<12d}{c.reset} Suppressed Inline   : {c.bold}{summary.suppressed_findings:<18d}{c.reset}{c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset}  Elapsed Time       : {c.bold}{summary.elapsed_ms:>8.2f} ms{c.reset}                                            {c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}├──────────────────────────────────────────────────────────────────────────────┤{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset}  Severity Breakdown : "
        f"{c.red}CRITICAL: {crit_cnt:<4d}{c.reset} "
        f"{c.red}HIGH: {high_cnt:<4d}{c.reset} "
        f"{c.yellow}MEDIUM: {med_cnt:<4d}{c.reset} "
        f"{c.cyan}LOW: {low_cnt:<4d}{c.reset}     {c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}│{c.reset}  Languages Scanned  : {langs_summary[:54]:<54s} {c.bold}{c.cyan}│{c.reset}"
    )
    out.append(
        f"{c.bold}{c.cyan}└──────────────────────────────────────────────────────────────────────────────┘{c.reset}"
    )
    return "\n".join(out)


def format_json_report(summary: ScanSummary) -> str:
    """Serialize findings and execution telemetry to structured JSON."""
    payload = {
        "tool": {
            "name": __tool_name__,
            "version": __version__,
        },
        "summary": {
            "root_path": summary.root_path,
            "files_scanned": summary.files_scanned,
            "loc_counted": summary.loc_counted,
            "total_findings": len(summary.findings),
            "suppressed_findings": summary.suppressed_findings,
            "elapsed_ms": round(summary.elapsed_ms, 2),
            "severity_breakdown": summary.severity_breakdown,
            "languages_breakdown": summary.languages_breakdown,
        },
        "findings": [f.to_dict() for f in summary.findings],
    }
    return json.dumps(payload, indent=2)


def format_sarif_report(summary: ScanSummary, rules: Sequence[Rule]) -> str:
    """
    Generate OASIS SARIF 2.1.0 compliant JSON report fully compatible with
    GitHub Code Scanning / Security Alerts.
    """
    rule_index_map: Dict[str, int] = {}
    sarif_rules: List[Dict[str, Any]] = []

    catalog = list(rules)
    if any(f.rule_id == "UNI-SEC-005" for f in summary.findings) and not any(
        r.id == "UNI-SEC-005" for r in catalog
    ):
        catalog.append(
            Rule(
                id="UNI-SEC-005",
                name="High-Entropy Hardcoded Secret Assignment",
                languages=ALL_LANGUAGES,
                severity=Severity.HIGH,
                cwe="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                description="High-entropy secret literal assigned to a sensitive credential variable.",
                remediation="Move secrets out of source code into environment variables or a secret manager.",
                pattern=SECRET_ASSIGNMENT_RE,
            )
        )

    for idx, rule in enumerate(catalog):
        rule_index_map[rule.id] = idx
        cwe_num = rule.cwe.split("-")[-1] if "-" in rule.cwe else rule.cwe
        sarif_rules.append(
            {
                "id": rule.id,
                "name": re.sub(r"[^A-Za-z0-9]", "", rule.name),
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "help": {
                    "text": f"{rule.description}\n\nRemediation: {rule.remediation}",
                    "markdown": f"**{rule.name}** (`{rule.cwe}` / `{rule.owasp}`)\n\n{rule.description}\n\n**Remediation:** {rule.remediation}",
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "defaultConfiguration": {
                    "level": rule.severity.to_sarif_level(),
                },
                "properties": {
                    "tags": [
                        "security",
                        f"external/cwe/{rule.cwe.lower()}",
                        rule.owasp,
                        *rule.languages,
                    ],
                    "precision": "high",
                    "problem.severity": rule.severity.to_sarif_level(),
                    "security-severity": rule.severity.to_security_severity_score(),
                },
            }
        )

    sarif_results: List[Dict[str, Any]] = []
    for finding in summary.findings:
        sev_enum = Severity.from_str(finding.severity)
        context_block = "\n".join(f"{c.line_number}: {c.content}" for c in finding.context)
        result_entry: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index_map.get(finding.rule_id, 0),
            "level": sev_enum.to_sarif_level(),
            "message": {
                "text": f"{finding.message} Remediation: {finding.remediation}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.lstrip("/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column,
                            "endLine": finding.line,
                            "endColumn": finding.end_column,
                            "snippet": {"text": finding.matched_text},
                        },
                        "contextRegion": {
                            "startLine": finding.context[0].line_number if finding.context else finding.line,
                            "endLine": finding.context[-1].line_number if finding.context else finding.line,
                            "snippet": {"text": context_block},
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint,
            },
            "properties": {
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "language": finding.language,
                "severity": finding.severity,
            },
        }
        sarif_results.append(result_entry)

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": __tool_name__,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": __tool_uri__,
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


# =============================================================================
# 9. CLI INTERFACE & ENTRYPOINT
# =============================================================================


def parse_language_filter(raw_lang_arg: Optional[str]) -> Set[str]:
    """Parse comma-separated `--lang` list and validate against the 11 supported languages."""
    if not raw_lang_arg:
        return set(LANGUAGE_EXTENSIONS.keys())
    resolved: Set[str] = set()
    unknown: List[str] = []
    for token in raw_lang_arg.split(","):
        cleaned = token.strip().lower()
        if not cleaned:
            continue
        canonical = LANGUAGE_ALIASES.get(cleaned)
        if canonical:
            resolved.add(canonical)
        else:
            unknown.append(token.strip())
    if unknown:
        valid_list = ", ".join(sorted(LANGUAGE_EXTENSIONS.keys()))
        raise ValueError(
            f"Unsupported language(s): {', '.join(unknown)}. Supported languages: {valid_list}"
        )
    return resolved


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polyscan",
        description=(
            "POLY//SCAN — Universal Multi-Language Static Code Analyzer & Security Linter "
            "(Java, C, C++, Objective-C, C#, Python, JavaScript, PHP, Go, Rust, Ruby)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="Target folder or file to scan (default: '.')",
    )
    parser.add_argument(
        "--lang",
        type=str,
        default=None,
        help="Comma-separated list of languages to restrict analysis to (e.g., python,go,rust)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        default="LOW",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        help="Minimum severity filter (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="text",
        choices=["text", "json", "sarif"],
        help="Output report format (text, json, sarif)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write results directly to a file (e.g., results.sarif)",
    )
    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        type=str,
        default=None,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        help="Exit with non-zero code (1) if vulnerabilities at or above this severity are found",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal text output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        allowed_languages = parse_language_filter(args.lang)
        min_severity = Severity.from_str(args.severity)
        fail_on_severity = Severity.from_str(args.fail_on) if args.fail_on else None
        target_path = Path(args.path)

        engine = PolyScanEngine(
            min_severity=min_severity,
            allowed_languages=allowed_languages,
        )
        summary = engine.scan_target(target_path)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[POLY//SCAN ERROR] {exc}", file=sys.stderr)
        return 2

    fmt = args.format.lower()
    if fmt == "json":
        rendered = format_json_report(summary)
    elif fmt == "sarif":
        rendered = format_sarif_report(summary, engine.all_rules)
    else:
        use_color = (not args.no_color) and (args.output is None)
        rendered = format_terminal_report(summary, use_color=use_color)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        if fmt != "text":
            print(
                f"[POLY//SCAN] Wrote {fmt.upper()} report ({len(summary.findings)} findings across "
                f"{summary.files_scanned} files in {summary.elapsed_ms:.2f} ms) -> {output_path}",
                file=sys.stderr,
            )
    else:
        print(rendered)

    if fail_on_severity is not None:
        breached = any(
            Severity.from_str(f.severity) >= fail_on_severity for f in summary.findings
        )
        if breached:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())