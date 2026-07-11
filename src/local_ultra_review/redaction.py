"""Known-sensitive classification and accepted-sink guards for V2."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from pathlib import PurePosixPath

from .contracts import sha256_json


class SensitiveMaterialError(ValueError):
    """Raised before known-sensitive material reaches an accepted sink."""


@dataclass(frozen=True)
class RedactionResult:
    safe_diff_text: str
    manual_dispositions: tuple[dict, ...]
    ruleset_hash: str


_RULESET_VERSION = "known-sensitive-v1"
_SENSITIVE_KEY = re.compile(
    r"^(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|private[_-]?key)$",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_PROVIDER_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
)
_ASSIGNMENT = re.compile(
    r"(?i)(?:[\"']?)(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|private[_-]?key)"
    r"(?:[\"']?)\s*[=:]\s*(?P<quote>[\"']?)"
    r"(?P<value>(?!(?:redacted|placeholder|example|dummy|none|null)(?:\b|$))"
    r"[^\s\"',#}\]]{8,})(?P=quote)"
)
_SENSITIVE_BASENAMES = {
    "credentials",
    "credentials.json",
    "secrets.json",
    "token.json",
    "tokens.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    ".netrc",
    "_netrc",
}
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db")
_SAFE_PLACEHOLDERS = {"", "redacted", "placeholder", "example", "dummy", "none", "null"}

RULESET_HASH = sha256_json(
    {
        "version": _RULESET_VERSION,
        "detectors": [
            "private_key",
            "github_token",
            "openai_key",
            "aws_access_key",
            "slack_token",
            "secret_assignment",
        ],
        "sensitive_basenames": sorted(_SENSITIVE_BASENAMES),
        "sensitive_suffixes": list(_SENSITIVE_SUFFIXES),
    }
)


def is_sensitive_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name.startswith(".env"):
        return True
    if name in _SENSITIVE_BASENAMES or name.endswith(_SENSITIVE_SUFFIXES):
        return True
    return any(part.lower() in {"credentials", "secrets", ".secrets"} for part in pure.parts)


def _hunks_for_range(text: str, start: int, end: int) -> tuple[str | None, ...]:
    headers = list(re.finditer(r"(?m)^@@[^\n]*@@[^\n]*$", text))
    affected = []
    for index, header in enumerate(headers):
        span_end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        if start < span_end and end > header.start():
            affected.append(header.group(0))
    return tuple(affected) if affected else (None,)


def _redact_text(text: str, path: str) -> tuple[str, tuple[dict, ...]]:
    matches: list[tuple[int, int, int, str]] = []
    for match in _PRIVATE_KEY.finditer(text):
        matches.append((match.start(), match.end(), 0, "private_key"))
    for reason, pattern in _PROVIDER_TOKENS:
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end(), 2, reason))
    for match in _ASSIGNMENT.finditer(text):
        matches.append((match.start("value"), match.end("value"), 1, "secret_assignment"))
    matches.sort(key=lambda item: (item[0], item[2], -(item[1] - item[0])))

    selected: list[tuple[int, int, str]] = []
    occupied_until = -1
    for start, end, _priority, reason in matches:
        if start < occupied_until:
            continue
        selected.append((start, end, reason))
        occupied_until = end
    if not selected:
        return text, ()

    pieces: list[str] = []
    cursor = 0
    dispositions: list[dict] = []
    seen_hunks: set[str | None] = set()
    for ordinal, (start, end, reason) in enumerate(selected, start=1):
        pieces.append(text[cursor:start])
        pieces.append(f"[REDACTED:{reason}:{ordinal}]")
        for hunk_header in _hunks_for_range(text, start, end):
            if hunk_header not in seen_hunks:
                dispositions.append(
                    {
                        "path": path,
                        "reason": "sensitive_content_redacted",
                        "hunk_header": hunk_header,
                    }
                )
                seen_hunks.add(hunk_header)
        cursor = end
    pieces.append(text[cursor:])
    redacted = "".join(pieces)
    redacted = re.sub(
        r"(?m)^index [0-9a-f]+\.\.[0-9a-f]+(?: [0-7]{6})?\n",
        "",
        redacted,
    )
    return redacted, tuple(dispositions)


def classify_and_redact_diff(
    raw_diff: bytes, path_records: tuple[dict, ...]
) -> RedactionResult:
    """Return a safe representation for one fixed-path Git diff."""

    if len(path_records) != 1:
        raise ValueError("redaction requires exactly one path record")
    record = path_records[0]
    path = record.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("path record requires a nonempty path")

    if is_sensitive_path(path):
        return RedactionResult(
            safe_diff_text=f"diff --git {path}\n[WITHHELD:sensitive_path]\n",
            manual_dispositions=(
                {"path": path, "reason": "sensitive_path", "hunk_header": None},
            ),
            ruleset_hash=RULESET_HASH,
        )

    special_reason = record.get("special_reason")
    if special_reason:
        return RedactionResult(
            safe_diff_text=f"diff --git {path}\n[WITHHELD:{special_reason}]\n",
            manual_dispositions=(
                {"path": path, "reason": str(special_reason), "hunk_header": None},
            ),
            ruleset_hash=RULESET_HASH,
        )

    if record.get("binary"):
        return RedactionResult(
            safe_diff_text=f"diff --git {path}\n[WITHHELD:binary_content]\n",
            manual_dispositions=(
                {"path": path, "reason": "binary_content", "hunk_header": None},
            ),
            ruleset_hash=RULESET_HASH,
        )

    try:
        text = raw_diff.decode("utf-8")
    except UnicodeDecodeError:
        return RedactionResult(
            safe_diff_text=f"diff --git {path}\n[WITHHELD:undecodable_text]\n",
            manual_dispositions=(
                {"path": path, "reason": "undecodable_text", "hunk_header": None},
            ),
            ruleset_hash=RULESET_HASH,
        )
    safe_text, dispositions = _redact_text(text, path)
    return RedactionResult(safe_text, dispositions, RULESET_HASH)


def _unsafe_string(value: str) -> bool:
    if _PRIVATE_KEY.search(value) or _ASSIGNMENT.search(value):
        return True
    return any(pattern.search(value) for _reason, pattern in _PROVIDER_TOKENS)


def assert_safe_sink(value: object) -> None:
    """Reject known-sensitive values before any accepted persistence sink."""

    def walk(node: object) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if isinstance(key, str) and _SENSITIVE_KEY.fullmatch(key) and isinstance(child, str):
                    normalized = child.strip().strip("\"'").lower()
                    if normalized not in _SAFE_PLACEHOLDERS:
                        raise SensitiveMaterialError("known-sensitive assignment rejected")
                walk(child)
            return
        if isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
            for child in node:
                walk(child)
            return
        if isinstance(node, bytes):
            text = node.decode("utf-8", errors="ignore")
        elif isinstance(node, str):
            text = node
        else:
            return
        if _unsafe_string(text):
            raise SensitiveMaterialError("known-sensitive material rejected")

    walk(value)
