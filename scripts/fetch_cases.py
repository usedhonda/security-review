#!/usr/bin/env python3
"""Fetch explicitly pinned public samples without running repository code."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
from typing import Any
from urllib import error, parse, request

MAX_MANIFEST_BYTES = 256_000
MAX_METADATA_BYTES = 256_000
MAX_FILE_BYTES = 300_000
MAX_CASE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 3_000_000
MAX_CASES = 12
MAX_FILES_PER_CASE = 256
REQUEST_TIMEOUT_SECONDS = 20


class FetchError(Exception):
    """A bounded, public error message that never embeds response contents."""


@dataclass(frozen=True)
class FileSpec:
    path: str
    git_blob_sha: str
    sha256: str | None


@dataclass(frozen=True)
class CaseSpec:
    repository: str
    commit: str
    root_parts: tuple[str, ...]
    files: tuple[FileSpec, ...]


@dataclass(frozen=True)
class FetchStats:
    cases: int
    files: int
    source_bytes: int
    cache_hits: int


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError("HTTP redirects are not allowed.")


def build_opener() -> request.OpenerDirector:
    # Ignore proxy environment variables, which may contain credentials. No
    # authentication, cookie, or netrc handlers are installed.
    return request.build_opener(request.ProxyHandler({}), NoRedirect())


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise FetchError("Invalid source file path.")
    if (
        PurePosixPath(value).is_absolute()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise FetchError("Source file paths must be normalized relative paths.")
    return value


def _digest(value: Any, size: int, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[a-fA-F0-9]{{{size}}}", value):
        raise FetchError(label)
    return value.lower()


def _directory_fd(project_root: Path, parts: tuple[str, ...], *, create: bool) -> int | None:
    """Walk beneath an open root directory; never follow a symlink component."""
    descriptor: int | None = None
    try:
        descriptor = os.open(project_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except FileNotFoundError:
        if descriptor is not None:
            os.close(descriptor)
        if not create:
            return None
        raise FetchError("The source cache directory could not be created.") from None
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise FetchError("Source cache directories must be real directories without symlinks.") from None


def _read_local(project_root: Path, parts: tuple[str, ...], limit: int) -> bytes | None:
    parent = _directory_fd(project_root, parts[:-1], create=False)
    if parent is None:
        return None
    try:
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise FetchError("Cached source paths must be regular files without symlinks.")
            if info.st_size > limit:
                raise FetchError("Source bytes exceed the configured fetch limits.")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise FetchError("Source bytes exceed the configured fetch limits.")
        return data
    except OSError:
        raise FetchError("A cached source file could not be read safely.") from None
    finally:
        os.close(parent)


def _write_new(project_root: Path, parts: tuple[str, ...], data: bytes) -> None:
    parent = _directory_fd(project_root, parts[:-1], create=True)
    assert parent is not None
    temporary = ".fetch-" + secrets.token_hex(16)
    created = False
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent,
        )
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        # Linking then removing the temporary name publishes a complete file
        # atomically and refuses to replace any concurrently created path.
        os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise FetchError("A verified source file could not be saved safely.") from None
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
        os.close(parent)


def load_manifest(manifest_path: Path, project_root: Path) -> tuple[CaseSpec, ...]:
    manifest_path = Path(os.path.abspath(manifest_path))
    try:
        manifest_parts = manifest_path.relative_to(project_root).parts
    except ValueError:
        raise FetchError("The manifest must be inside this project.") from None
    if not manifest_parts:
        raise FetchError("The manifest must be a JSON file.")
    raw = _read_local(project_root, manifest_parts, MAX_MANIFEST_BYTES)
    if raw is None:
        raise FetchError("The manifest could not be read.")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise FetchError("The manifest must contain UTF-8 JSON.") from None
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise FetchError("Manifest schema_version must be 1.")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= MAX_CASES:
        raise FetchError("The manifest must contain between 1 and 12 cases.")
    cases: list[CaseSpec] = []
    case_ids: set[str] = set()
    allowed_root = project_root / ".work" / "sources"
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise FetchError("Each case must be an object.")
        case_id = raw_case.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case_id) or case_id in case_ids:
            raise FetchError("Case identifiers must be valid and unique.")
        case_ids.add(case_id)
        repository = raw_case.get("repository")
        if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repository) or repository.split("/")[1] in (".", ".."):
            raise FetchError("Repository must be a GitHub owner/name.")
        commit = _digest(raw_case.get("commit"), 40, "Each case requires a full commit SHA.")
        source_root = raw_case.get("source_root")
        if not isinstance(source_root, str) or not source_root or len(source_root) > 512 or "\\" in source_root or PurePosixPath(source_root).is_absolute() or any(ord(character) < 32 or ord(character) == 127 for character in source_root):
            raise FetchError("source_root must be a relative source cache directory.")
        root_components = source_root.split("/")
        reached_directory = False
        for component in root_components:
            if component in ("", ".") or (component == ".." and reached_directory):
                raise FetchError("source_root must be normalized; parent references may only lead the path.")
            reached_directory = reached_directory or component != ".."
        source_path = Path(os.path.abspath(manifest_path.parent / source_root))
        if source_path == allowed_root or not source_path.is_relative_to(allowed_root):
            raise FetchError("source_root must stay below this project's .work/sources directory.")
        root_parts = source_path.relative_to(project_root).parts
        raw_files = raw_case.get("files")
        if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_FILES_PER_CASE:
            raise FetchError("Each case requires between 1 and 256 explicit file selections.")
        files: list[FileSpec] = []
        seen: set[str] = set()
        for raw_file in raw_files:
            if isinstance(raw_file, str):
                raise FetchError("Fetching requires file objects with path and git_blob_sha.")
            if not isinstance(raw_file, dict):
                raise FetchError("Each file selection must be an object.")
            relative = _relative_path(raw_file.get("path"))
            if relative in seen:
                raise FetchError("Duplicate files are not allowed within a case.")
            seen.add(relative)
            blob_sha = _digest(raw_file.get("git_blob_sha"), 40, "Every fetched file requires git_blob_sha.")
            sha256 = None if raw_file.get("sha256") is None else _digest(raw_file["sha256"], 64, "Invalid optional sha256 digest.")
            files.append(FileSpec(relative, blob_sha, sha256))
        cases.append(CaseSpec(repository, commit, root_parts, tuple(files)))
    return tuple(cases)


def _http_read(opener: request.OpenerDirector, url: str, limit: int, *, metadata: bool = False) -> bytes:
    headers = {
        "User-Agent": "security-review-lab/0.1",
        "Accept": "application/vnd.github+json" if metadata else "text/plain",
        "Accept-Encoding": "identity",
    }
    if metadata:
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.geturl() != url or response.getcode() != 200:
                raise FetchError("Only direct successful GitHub responses are accepted.")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > limit):
                raise FetchError("A GitHub response exceeds the configured fetch limits.")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise FetchError("A GitHub response exceeds the configured fetch limits.")
        return data
    except (error.URLError, OSError, ValueError, http.client.HTTPException):
        raise FetchError("A public GitHub resource could not be downloaded safely.") from None


def _verify_commit(opener: request.OpenerDirector, case: CaseSpec, remaining: int) -> int:
    url = f"https://api.github.com/repos/{case.repository}/git/commits/{case.commit}"
    raw = _http_read(opener, url, min(MAX_METADATA_BYTES, remaining), metadata=True)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise FetchError("GitHub commit metadata is invalid.") from None
    if (
        not isinstance(payload, dict)
        or payload.get("sha") != case.commit
        or not isinstance(payload.get("tree"), dict)
        or not isinstance(payload["tree"].get("sha"), str)
        or not re.fullmatch(r"[a-f0-9]{40}", payload["tree"]["sha"])
        or not isinstance(payload.get("parents"), list)
    ):
        raise FetchError("The pinned SHA was not verified as a Git commit.")
    return len(raw)


def _verify_source(data: bytes, selected: FileSpec) -> None:
    blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != selected.git_blob_sha:
        raise FetchError("A source file does not match its pinned Git blob digest.")
    if selected.sha256 is not None and hashlib.sha256(data).hexdigest() != selected.sha256:
        raise FetchError("A source file does not match its optional SHA-256 digest.")
    try:
        content = data.decode("utf-8")
    except UnicodeError:
        raise FetchError("Source files must be UTF-8 text.") from None
    if any((ord(character) < 32 and character not in "\t\r\n") or ord(character) == 127 for character in content):
        raise FetchError("Binary or control-character source content is not accepted.")


def fetch_manifest(
    manifest_path: Path,
    *,
    project_root: Path | None = None,
    opener: request.OpenerDirector | None = None,
) -> FetchStats:
    project_root = (project_root or Path(__file__).resolve().parent.parent).resolve()
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise FetchError("Safe source acquisition requires a POSIX filesystem.")
    cases = load_manifest(manifest_path, project_root)
    opener = opener or build_opener()
    total_bytes = 0
    source_bytes = 0
    file_count = 0
    cache_hits = 0
    verified_commits: set[tuple[str, str]] = set()
    for case in cases:
        key = (case.repository, case.commit)
        if key not in verified_commits:
            total_bytes += _verify_commit(opener, case, MAX_TOTAL_BYTES - total_bytes)
            verified_commits.add(key)
        case_bytes = 0
        for selected in case.files:
            limit = min(MAX_FILE_BYTES, MAX_CASE_BYTES - case_bytes, MAX_TOTAL_BYTES - total_bytes)
            parts = case.root_parts + PurePosixPath(selected.path).parts
            data = _read_local(project_root, parts, limit)
            cached = data is not None
            if data is None:
                url = f"https://raw.githubusercontent.com/{case.repository}/{case.commit}/{parse.quote(selected.path, safe='/')}"
                data = _http_read(opener, url, limit)
            _verify_source(data, selected)
            if not cached:
                _write_new(project_root, parts, data)
            total_bytes += len(data)
            source_bytes += len(data)
            case_bytes += len(data)
            file_count += 1
            cache_hits += int(cached)
    return FetchStats(len(cases), file_count, source_bytes, cache_hits)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = fetch_manifest(args.manifest)
    except FetchError as problem:
        print(f"Source fetch stopped: {problem}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError):
        print("Source fetch stopped: an unexpected local or network error occurred.", file=sys.stderr)
        return 2
    print(f"Verified {result.files} files in {result.cases} cases: {result.source_bytes} bytes; {result.cache_hits} files reused from cache.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
