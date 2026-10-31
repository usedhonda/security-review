"""Fail-closed filesystem and billing checks; never copy untrusted error text."""
from __future__ import annotations

from datetime import date
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from .safety import ReviewError


def directory_fd(path: Path, *, create: bool = False) -> int:
    """Open every directory component without following symlinks (POSIX only)."""
    if not all(hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK')):
        raise ReviewError('Safe file access requires a POSIX filesystem.')
    absolute = Path(os.path.abspath(path))
    current = None
    try:
        current = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in absolute.parts[1:]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except (OSError, ValueError):
        if current is not None:
            os.close(current)
        raise ReviewError('Directory access failed; symlink components are not allowed.') from None


def read_file(path: Path, limit: int) -> bytes:
    """Bound the read before allocation; reject links, devices, directories and FIFOs."""
    parent = directory_fd(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ReviewError('Input must be a regular file within its byte limit.')
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ReviewError('Input exceeds its byte limit.')
        return content
    except (OSError, ValueError):
        raise ReviewError('Input file could not be read safely.') from None
    finally:
        os.close(parent)


def claim_output(path: Path) -> None:
    """Retain an exclusive marker even after interruption; never silently reuse a run."""
    parent = directory_fd(path, create=True)
    try:
        for name in ('summary.json', 'summary.md'):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ReviewError('Output already exists; use a fresh directory.')
        descriptor = os.open('.run.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(b'Run directory claimed; inspect prior usage before any retry.\n')
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ReviewError('Output is already claimed or cannot be created safely; use a fresh directory.') from None
    finally:
        os.close(parent)


def write_report(path: Path, content: str) -> None:
    """Atomically replace a report using directory-relative operations, mode 0600."""
    parent = directory_fd(path.parent)
    temporary = '.report-' + secrets.token_hex(16)
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        created = True
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
    except OSError:
        raise ReviewError('Report could not be written safely.') from None
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(parent)


def billing_matches(response: dict[str, Any], model: str) -> bool:
    """Only the requested model or a dated snapshot, explicit standard tier/mode."""
    actual = response.get('model')
    model_ok = actual == model
    if isinstance(actual, str) and actual.startswith(model + '-'):
        suffix = actual[len(model) + 1:]
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', suffix):
            try:
                date.fromisoformat(suffix)
                model_ok = True
            except ValueError:
                pass
    tier = response.get('service_tier')
    reasoning = response.get('reasoning')
    return (model_ok and isinstance(tier, str) and tier in ('default', 'standard')
            and isinstance(reasoning, dict) and reasoning.get('mode') == 'standard')


def http_status(error: BaseException) -> int | None:
    """Extract only the fixed safe error format emitted by our API transport."""
    if not isinstance(error, ReviewError):
        return None
    match = re.fullmatch(r'API request failed with HTTP ([1-5][0-9]{2}); no retry was made\.', str(error))
    return int(match.group(1)) if match else None
