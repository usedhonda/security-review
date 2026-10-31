"""Read bounded UTF-8 source excerpts without importing or executing them."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from .safety import Redactor, ReviewError, safe_integer

MAX_MANIFEST_BYTES = 256_000
MAX_FILE_BYTES = 2_000_000
MAX_CASE_BYTES = 196_608
MAX_FILES = 256
MAX_CASES = 12


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ReviewError("Invalid source path.")
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or any(ord(char) < 32 for char in value):
        raise ReviewError("Unsafe source path.")
    if any(part in (".", "..", "") for part in value.split("/")):
        raise ReviewError("Unsafe source path.")
    return value


def _excluded(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower()
    return (
        any(part.lower() in {".git", ".ssh", ".aws", "node_modules", "vendor", ".venv", "__pycache__"} for part in parts)
        or name.startswith(".env")
        or name in {"id_rsa", "id_ed25519", "credentials", "credentials.json", "auth.json"}
        or name.endswith((".pem", ".p12", ".pfx", ".key", ".keystore"))
    )


def _read_source(root: Path, relative: str) -> bytes:
    current = root
    try:
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise ReviewError("Symlink source paths are not allowed.")
        if not current.resolve().is_relative_to(root):
            raise ReviewError("Source path escapes its root.")
        fd = os.open(current, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ReviewError("Source path is not a regular file.")
            if info.st_size > MAX_FILE_BYTES:
                raise ReviewError("A source file exceeds the 2 MB read limit.")
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ReviewError("A source file exceeds the 2 MB read limit.")
        return data
    except OSError:
        raise ReviewError("A source file could not be read.") from None


def load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ReviewError("Manifest exceeds the 256 KB limit.")
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ReviewError("Manifest must be a readable UTF-8 JSON document.") from None
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ReviewError("Manifest schema_version must be 1.")
    cases = document.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ReviewError("Manifest must contain 1 to 12 cases.")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ReviewError("Invalid case.")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case_id) or case_id in seen:
            raise ReviewError("Case IDs must be unique, short identifiers.")
        seen.add(case_id)
        if not isinstance(case.get("repository"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", case["repository"]):
            raise ReviewError("Each case needs an owner/repository name.")
        if not isinstance(case.get("commit"), str) or not re.fullmatch(r"[a-fA-F0-9]{40}", case["commit"]):
            raise ReviewError("Each case needs a full 40-character commit SHA.")
        if case.get("mode", "snapshot") not in {"snapshot", "diff"}:
            raise ReviewError("Case mode must be snapshot or diff.")
        if case.get("mode") == "diff" and not re.fullmatch(r"[a-fA-F0-9]{40}", str(case.get("base_commit", ""))):
            raise ReviewError("Diff cases need a full base_commit SHA.")
        if not isinstance(case.get("source_root"), str) or not case["source_root"]:
            raise ReviewError("Each case needs source_root.")
        files = case.get("files")
        if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
            raise ReviewError("Each case needs 1 to 256 explicitly selected files.")
        context = case.get("context", "")
        if not isinstance(context, str) or len(context.encode("utf-8")) > 8000:
            raise ReviewError("Case context exceeds the 8 KB limit.")
        safe_integer(case.get("max_source_bytes", 48_000), "max_source_bytes", 1, MAX_CASE_BYTES)
    return cases


def _ranges(spec: Any, line_count: int, is_diff: bool) -> list[list[int]]:
    if spec is None:
        if is_diff:
            raise ReviewError("Diff files require explicit head-side line_ranges.")
        return [[1, line_count]] if line_count else []
    if not isinstance(spec, list) or len(spec) > 256:
        raise ReviewError("Invalid line_ranges.")
    ranges: list[list[int]] = []
    last_end = 0
    for interval in spec:
        if not isinstance(interval, list) or len(interval) != 2:
            raise ReviewError("Line ranges must be [start, end] pairs.")
        start = safe_integer(interval[0], "range start", 1, max(1, line_count))
        end = safe_integer(interval[1], "range end", start, max(1, line_count))
        if start <= last_end or not line_count:
            raise ReviewError("Line ranges must be non-overlapping and within the file.")
        ranges.append([start, end])
        last_end = end
    return ranges


def prepare_case(case: dict[str, Any], manifest_dir: Path, redactor: Redactor) -> dict[str, Any]:
    root = manifest_dir / case["source_root"]
    if root.is_symlink() or not root.is_dir():
        raise ReviewError("source_root must be a real directory.")
    root = root.resolve()
    remaining = case.get("max_source_bytes", 48_000)
    files: list[dict[str, Any]] = []
    excerpts: list[dict[str, Any]] = []
    seen: set[str] = set()
    redactions_before = redactor.redactions
    total_read_bytes = 0
    for item in case["files"]:
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict):
            raise ReviewError("Each source file must be a path or a file selection object.")
        relative = _safe_path(item.get("path"))
        if redactor.text(relative) != relative:
            raise ReviewError("Credential-like source filenames cannot be reviewed.")
        if relative in seen:
            raise ReviewError("Duplicate source file selection.")
        seen.add(relative)
        info: dict[str, Any] = {"path": relative, "source_bytes": None, "source_lines": None, "selected_bytes": 0, "selected_lines": 0, "included_bytes": 0, "included_lines": 0, "included_ranges": [], "sha256": None, "status": "excluded"}
        files.append(info)
        if _excluded(relative):
            info["reason"] = "excluded_path"
            continue
        data = _read_source(root, relative)
        total_read_bytes += len(data)
        if total_read_bytes > 16_000_000:
            raise ReviewError("Selected files exceed the 16 MB per-case read limit.")
        info["source_bytes"] = len(data)
        info["sha256"] = hashlib.sha256(data).hexdigest()
        expected_hash = item.get("sha256")
        if expected_hash is not None and expected_hash != info["sha256"]:
            raise ReviewError("Source digest does not match manifest sha256.")
        try:
            content = data.decode("utf-8")
        except UnicodeError:
            info["reason"] = "non_utf8"
            continue
        if "\x00" in content:
            info["reason"] = "binary"
            continue
        lines = content.splitlines(keepends=True)
        info["source_lines"] = len(lines)
        ranges = _ranges(item.get("line_ranges"), len(lines), case.get("mode") == "diff")
        selected = [number for start, end in ranges for number in range(start, end + 1)]
        info["selected_lines"] = len(selected)
        info["selected_bytes"] = sum(len(lines[number - 1].encode("utf-8")) for number in selected)
        clean_lines = redactor.text(content).splitlines(keepends=True)
        # Redaction preserves newlines; refuse a surprising line-count change.
        if len(clean_lines) != len(lines):
            raise ReviewError("Redaction changed source line boundaries.")
        excerpt_lines = []
        included_ranges: list[list[int]] = []
        for number in selected:
            byte_count = len(lines[number - 1].encode("utf-8"))
            if byte_count > remaining:
                break
            remaining -= byte_count
            info["included_bytes"] += byte_count
            info["included_lines"] += 1
            if included_ranges and included_ranges[-1][1] == number - 1:
                included_ranges[-1][1] = number
            else:
                included_ranges.append([number, number])
            excerpt_lines.append(f"{number}: {clean_lines[number - 1].rstrip(chr(10) + chr(13))}")
        info["included_ranges"] = included_ranges
        info["status"] = "included" if info["included_lines"] == info["selected_lines"] else "partial" if info["included_lines"] else "excluded"
        if info["included_lines"] < info["selected_lines"]:
            info["reason"] = "source_byte_limit"
        if excerpt_lines:
            excerpts.append({"path": relative, "numbered_source": "\n".join(excerpt_lines)})
    coverage = {
        "basis": "explicitly_selected_files_and_ranges; not_entire_repository",
        "requested_files": len(files),
        "included_files": sum(bool(item["included_lines"]) for item in files),
        "source_bytes": sum(item["source_bytes"] or 0 for item in files),
        "source_lines": sum(item["source_lines"] or 0 for item in files),
        "selected_bytes": sum(item["selected_bytes"] for item in files),
        "selected_lines": sum(item["selected_lines"] for item in files),
        "included_bytes": sum(item["included_bytes"] for item in files),
        "included_lines": sum(item["included_lines"] for item in files),
        "complete_for_selection": all(item["status"] == "included" for item in files),
        "redactions": redactor.redactions - redactions_before,
        "files": files,
    }
    selected_bytes = coverage["selected_bytes"]
    coverage["selected_byte_fraction"] = round(coverage["included_bytes"] / selected_bytes, 6) if selected_bytes else 0
    public = {"id": case["id"], "repository": case["repository"], "commit": case["commit"].lower(), "mode": case.get("mode", "snapshot"), "coverage": coverage, "provenance": "manifest_commit_and_local_file_sha256; acquisition_must_verify_commit"}
    if case.get("base_commit"):
        public["base_commit"] = case["base_commit"].lower()
    return {"public": public, "data": {"repository": case["repository"], "commit": case["commit"].lower(), "mode": case.get("mode", "snapshot"), "context": redactor.text(case.get("context", "")), "scope": coverage, "files": excerpts}}
