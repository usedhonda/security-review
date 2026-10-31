"""Encrypt detailed reports with age; never upload or log plaintext as a fallback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any

from .guards import claim_output, directory_fd, read_file, write_report
from .safety import ReviewError

FORMAT = 'security-review.age-bundle.v1'
ARTIFACT_FILE = 'report.json.age'
MAX_FILE = 2_000_000
MAX_BUNDLE = 4_500_000
MAX_CIPHER = MAX_BUNDLE + 8192
MAGIC = b'age-encryption.org/v1\n'


def recipient(value: str) -> str:
    # One native X25519 recipient only. No identities, SSH keys, plugins or lists.
    value = value.strip()
    if not re.fullmatch(r'age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}', value):
        raise ReviewError('Set REVIEW_AGE_RECIPIENT to one native age public key, never a secret key.')
    return value


def _age(arguments: list[str], content: bytes) -> bytes:
    executable = shutil.which('age')
    if executable is None:
        raise ReviewError('The age executable is required; no plaintext fallback is available.')
    try:
        result = subprocess.run(
            [executable, *arguments], input=content, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
            # Never pass API credentials or workflow tokens to the encryption process.
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReviewError('Encryption/decryption failed; no report was released.') from None
    if result.returncode != 0 or len(result.stdout) > MAX_CIPHER:
        # age may produce partial plaintext before detecting a truncated stream.
        # Hold all output in memory and discard it unless the entire command succeeds.
        raise ReviewError('Encryption/decryption failed; no report was released.')
    return result.stdout


def encrypt(data: bytes, public_key: str) -> bytes:
    if len(data) > MAX_BUNDLE:
        raise ReviewError('Report bundle exceeds its size limit.')
    ciphertext = _age(['--encrypt', '--recipient', recipient(public_key)], data)
    if not ciphertext.startswith(MAGIC) or len(ciphertext) <= len(data):
        raise ReviewError('Encryption did not produce a valid bounded age file.')
    return ciphertext


def preflight(public_key: str) -> str:
    public_key = recipient(public_key)
    # age also validates the bech32 checksum. No API or real report is used.
    encrypt(b'security-review recovery preflight\n', public_key)
    return hashlib.sha256(public_key.encode('ascii')).hexdigest()


def context(kind: str, outcome: str) -> dict[str, str]:
    values = {
        'repository': os.environ.get('GITHUB_REPOSITORY', ''),
        'workflow_commit': os.environ.get('GITHUB_SHA', ''),
        'run_id': os.environ.get('GITHUB_RUN_ID', ''),
        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT', ''),
    }
    patterns = {'repository': r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',
                'workflow_commit': r'[a-f0-9]{40}', 'run_id': r'[1-9][0-9]{0,19}',
                'run_attempt': r'[1-9][0-9]{0,9}'}
    if any(not re.fullmatch(patterns[key], value) for key, value in values.items()):
        raise ReviewError('Valid GitHub run provenance is required.')
    if kind not in ('probe', 'review') or outcome not in ('success', 'failure', 'cancelled', 'skipped', 'unknown'):
        raise ReviewError('Invalid recovery context.')
    return {**values, 'kind': kind, 'step_outcome': outcome}


def seal(report_dir: Path | None, output_dir: Path, public_key: str,
         provenance: dict[str, str], *, probe: bool = False) -> None:
    fingerprint = preflight(public_key)
    if probe:
        report_json = json.dumps({'schema_version': 1, 'status': 'recovery_probe',
                                  'nonce': secrets.token_hex(16), 'api_calls': 0}, indent=2)
        report_markdown = '# Recovery check\n\nRecovery succeeded. This is synthetic data; no OpenAI API was called.\n'
    else:
        if report_dir is None:
            raise ReviewError('A report directory is required.')
        # Read only the atomic JSON checkpoint; rebuild Markdown from that same
        # snapshot rather than pairing it with a possibly older Markdown file.
        report_json = read_file(report_dir / 'summary.json', MAX_FILE).decode('utf-8')
        report = json.loads(report_json)
        if not isinstance(report, dict) or type(report.get('schema_version')) is not int or report['schema_version'] != 1:
            raise ReviewError('Unsupported report checkpoint.')
        from .reports import render_markdown
        report_markdown = render_markdown(report)
    if max(len(report_json.encode('utf-8')), len(report_markdown.encode('utf-8'))) > MAX_FILE:
        raise ReviewError('Detailed report exceeds its size limit.')
    bundle = {'format': FORMAT, 'provenance': {**provenance, 'recipient_sha256': fingerprint},
              'summary_json': report_json, 'summary_markdown': report_markdown}
    ciphertext = encrypt(json.dumps(bundle, ensure_ascii=False).encode('utf-8'), public_key)
    # Only successful complete encryption can create the allowlisted upload file.
    claim_output(output_dir)
    parent = directory_fd(output_dir)
    try:
        fd = os.open(ARTIFACT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(ciphertext)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(parent)


def restore(cipher_file: Path, identity: Path, output_dir: Path,
            expected: dict[str, str]) -> None:
    ciphertext = read_file(cipher_file, MAX_CIPHER)
    if not ciphertext.startswith(MAGIC):
        raise ReviewError('Expected an age encrypted report.')
    # A dedicated native identity file remains local. Validate the file boundary
    # without logging its contents; age itself performs the cryptography.
    identity_data = read_file(identity, 16_384)
    if b'AGE-SECRET-KEY-1' not in identity_data:
        raise ReviewError('A local native age identity file is required.')
    plaintext = _age(['--decrypt', '--identity', str(identity)], ciphertext)
    if len(plaintext) > MAX_BUNDLE:
        raise ReviewError('Decrypted report exceeds its size limit.')
    bundle = json.loads(plaintext)
    if not isinstance(bundle, dict) or set(bundle) != {'format', 'provenance', 'summary_json', 'summary_markdown'} or bundle['format'] != FORMAT:
        raise ReviewError('Unsupported encrypted report format.')
    provenance = bundle['provenance']
    if not isinstance(provenance, dict) or any(provenance.get(key) != value for key, value in expected.items()):
        raise ReviewError('Report provenance does not match the selected GitHub run.')
    for key in ('summary_json', 'summary_markdown'):
        value = bundle[key]
        if not isinstance(value, str) or len(value.encode('utf-8')) > MAX_FILE:
            raise ReviewError('Invalid decrypted report content.')
    # No archive extraction, path names from the payload, rendering or execution.
    claim_output(output_dir)
    write_report(output_dir / 'summary.json', bundle['summary_json'])
    write_report(output_dir / 'summary.md', bundle['summary_markdown'])
    write_report(output_dir / 'provenance.json', json.dumps(provenance, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('preflight')
    seal_cmd = commands.add_parser('seal')
    seal_cmd.add_argument('--report-dir', type=Path)
    seal_cmd.add_argument('--output-dir', type=Path, required=True)
    seal_cmd.add_argument('--probe', action='store_true')
    seal_cmd.add_argument('--outcome', choices=('success', 'failure', 'cancelled', 'skipped', 'unknown'), default='unknown')
    restore_cmd = commands.add_parser('restore')
    restore_cmd.add_argument('--input', type=Path, required=True)
    restore_cmd.add_argument('--identity', type=Path, required=True)
    restore_cmd.add_argument('--output-dir', type=Path, required=True)
    for name in ('repository', 'run-id', 'run-attempt', 'workflow-commit'):
        restore_cmd.add_argument('--expect-' + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'preflight':
            print('Recipient SHA-256: ' + preflight(os.environ.get('REVIEW_AGE_RECIPIENT', '')))
        elif args.command == 'seal':
            seal(args.report_dir, args.output_dir, os.environ.get('REVIEW_AGE_RECIPIENT', ''),
                 context('probe' if args.probe else 'review', args.outcome), probe=args.probe)
            print('Encrypted report prepared. No plaintext was published.')
        else:
            restore(args.input, args.identity, args.output_dir, {
                'repository': args.expect_repository, 'run_id': args.expect_run_id,
                'run_attempt': args.expect_run_attempt, 'workflow_commit': args.expect_workflow_commit,
            })
            print('Report restored locally. Treat its contents as untrusted text; nothing was executed.')
        return 0
    except (ReviewError, OSError, ValueError, UnicodeError, KeyError, TypeError, RecursionError):
        # Never echo invalid key material, model output, filenames or error bodies.
        print('Recovery failed. Check the key, run provenance and fresh output directory locally. No plaintext fallback.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
