"""Real age integration tests use disposable identities, never user secrets or APIs."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from security_review import recovery
from security_review.safety import ReviewError

PROVENANCE = {'repository': 'owner/repo', 'workflow_commit': 'a' * 40,
              'run_id': '123', 'run_attempt': '1', 'kind': 'probe', 'step_outcome': 'success'}
EXPECTED = {key: PROVENANCE[key] for key in ('repository', 'workflow_commit', 'run_id', 'run_attempt')}


class RecoveryUnitTests(unittest.TestCase):
    def test_private_keys_multiple_recipients_plugins_and_newlines_are_rejected(self):
        for value in ('', 'AGE-SECRET-KEY-1DO-NOT-PRINT', 'ssh-ed25519 AAAA',
                      'age1plugin', 'age1' + 'q' * 58 + '\nage1' + 'q' * 58):
            with self.subTest(value=value[:4]), self.assertRaises(ReviewError):
                recovery.recipient(value)

    def test_encryption_subprocess_does_not_inherit_credentials(self):
        fake = subprocess.CompletedProcess([], 0, recovery.MAGIC + b'x' * 100)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'must-not-inherit', 'GH_TOKEN': 'must-not-inherit'}), \
             patch.object(recovery.shutil, 'which', return_value='/usr/bin/age'), \
             patch.object(recovery.subprocess, 'run', return_value=fake) as run:
            recovery.encrypt(b'hello', 'age1' + 'q' * 58)
        call = run.call_args
        self.assertNotIn('OPENAI_API_KEY', call.kwargs['env'])
        self.assertNotIn('GH_TOKEN', call.kwargs['env'])
        self.assertEqual(call.kwargs['stderr'], subprocess.DEVNULL)
        self.assertNotIn('shell', call.kwargs)

    def test_failed_crypto_never_returns_partial_plaintext(self):
        fake = subprocess.CompletedProcess([], 1, b'private partial plaintext')
        with patch.object(recovery.shutil, 'which', return_value='/usr/bin/age'), \
             patch.object(recovery.subprocess, 'run', return_value=fake):
            with self.assertRaises(ReviewError) as caught:
                recovery._age(['--decrypt'], b'x')
        self.assertNotIn('private partial plaintext', str(caught.exception))

    def test_missing_age_has_no_fallback(self):
        with patch.object(recovery.shutil, 'which', return_value=None), self.assertRaises(ReviewError):
            recovery.preflight('age1' + 'q' * 58)

    def test_invalid_key_never_appears_in_cli_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {'REVIEW_AGE_RECIPIENT': 'AGE-SECRET-KEY-1DO-NOT-PRINT'}), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(recovery.main(['preflight']), 2)
        self.assertNotIn('DO-NOT-PRINT', stdout.getvalue() + stderr.getvalue())

    def test_invalid_run_metadata_is_not_reflected(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'private-invalid\nmetadata'}), \
             self.assertRaises(ReviewError) as caught:
                recovery.context('probe', 'success')
        self.assertNotIn('private-invalid', str(caught.exception))


class AgeRecoveryIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('age') or not shutil.which('age-keygen'):
            if os.environ.get('REQUIRE_AGE') == '1':
                raise AssertionError('CI must install age; real crypto tests may not be skipped.')
            raise unittest.SkipTest('Install age for real encryption round-trip tests.')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = self.root / 'identity.txt'
        subprocess.run(['age-keygen', '-o', str(self.identity)], check=True, capture_output=True)
        self.public = subprocess.run(['age-keygen', '-y', str(self.identity)], check=True, capture_output=True, text=True).stdout.strip()
        self.encrypted = self.root / 'encrypted'
        self.restored = self.root / 'restored'

    def make_probe(self):
        recovery.seal(None, self.encrypted, self.public, PROVENANCE, probe=True)
        return self.encrypted / recovery.ARTIFACT_FILE

    def test_real_round_trip_and_private_file_permissions(self):
        cipher = self.make_probe()
        self.assertNotIn(b'Recovery succeeded', cipher.read_bytes())
        self.assertNotIn(self.identity.read_bytes(), cipher.read_bytes())
        recovery.restore(cipher, self.identity, self.restored, EXPECTED)
        self.assertEqual(json.loads((self.restored / 'summary.json').read_text())['api_calls'], 0)
        self.assertIn('Recovery succeeded', (self.restored / 'summary.md').read_text())
        self.assertEqual(json.loads((self.restored / 'provenance.json').read_text())['run_id'], '123')
        for path in (cipher, self.restored / 'summary.json', self.restored / 'summary.md'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_real_report_checkpoint_round_trip_without_api(self):
        from security_review.cli import run_experiment
        source = self.root / 'source'
        source.mkdir()
        (source / 'app.py').write_text('print(1)\n')
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps({'schema_version': 1, 'cases': [{'id': 'sample',
            'repository': 'owner/repo', 'commit': 'b' * 40, 'source_root': 'source', 'files': ['app.py']}]}))
        reports = self.root / 'reports'
        run_experiment(manifest, reports)
        # A stale Markdown checkpoint must not be bundled with newer JSON.
        (reports / 'summary.md').write_text('STALE-REPORT')
        recovery.seal(reports, self.encrypted, self.public, {**PROVENANCE, 'kind': 'review'})
        recovery.restore(self.encrypted / recovery.ARTIFACT_FILE, self.identity, self.restored, EXPECTED)
        self.assertEqual(json.loads((self.restored / 'summary.json').read_text())['status'], 'planned')
        self.assertNotIn('STALE-REPORT', (self.restored / 'summary.md').read_text())
        self.assertIn('Security review experiment', (self.restored / 'summary.md').read_text())

    def test_wrong_identity_cannot_restore(self):
        cipher = self.make_probe()
        other = self.root / 'other.txt'
        subprocess.run(['age-keygen', '-o', str(other)], check=True, capture_output=True)
        with self.assertRaises(ReviewError):
            recovery.restore(cipher, other, self.restored, EXPECTED)
        self.assertFalse(self.restored.exists())

    def test_tampered_or_truncated_ciphertext_never_writes_plaintext(self):
        cipher = self.make_probe()
        original = cipher.read_bytes()
        variants = (original[:-1], original[:-1] + bytes([original[-1] ^ 1]))
        for damaged in variants:
            cipher.write_bytes(damaged)
            with self.assertRaises(ReviewError):
                recovery.restore(cipher, self.identity, self.restored, EXPECTED)
            self.assertFalse(self.restored.exists())

    def test_wrong_run_or_revision_is_rejected(self):
        cipher = self.make_probe()
        for key, value in (('run_id', '124'), ('run_attempt', '2'), ('workflow_commit', 'c' * 40), ('repository', 'other/repo')):
            with self.assertRaises(ReviewError):
                recovery.restore(cipher, self.identity, self.restored, {**EXPECTED, key: value})
            self.assertFalse(self.restored.exists())

    def test_invalid_checksum_stops_before_output(self):
        with self.assertRaises(ReviewError):
            recovery.seal(None, self.encrypted, 'age1' + 'q' * 58, PROVENANCE, probe=True)
        self.assertFalse(self.encrypted.exists())

    def test_output_reuse_is_rejected(self):
        cipher = self.make_probe()
        original = cipher.read_bytes()
        with self.assertRaises(ReviewError):
            self.make_probe()
        self.assertEqual(cipher.read_bytes(), original)
        recovery.restore(cipher, self.identity, self.restored, EXPECTED)
        with self.assertRaises(ReviewError):
            recovery.restore(cipher, self.identity, self.restored, EXPECTED)

    def test_report_symlink_is_rejected_without_upload_file(self):
        reports = self.root / 'reports'
        reports.mkdir()
        target = self.root / 'outside.json'
        target.write_text('{}')
        (reports / 'summary.json').symlink_to(target)
        with self.assertRaises(ReviewError):
            recovery.seal(reports, self.encrypted, self.public, PROVENANCE)
        self.assertFalse(self.encrypted.exists())

    def test_invalid_bundle_cannot_create_arbitrary_files(self):
        value = {'format': recovery.FORMAT, 'provenance': PROVENANCE,
                 'summary_json': '{}', 'summary_markdown': 'text', '../escape': 'never'}
        cipher = self.root / 'bad.age'
        cipher.write_bytes(recovery.encrypt(json.dumps(value).encode(), self.public))
        with self.assertRaises(ReviewError):
            recovery.restore(cipher, self.identity, self.restored, EXPECTED)
        self.assertFalse(self.restored.exists())

    def test_ciphertext_size_limit_prevents_decryption(self):
        cipher = self.root / 'oversized.age'
        with cipher.open('wb') as stream:
            stream.seek(recovery.MAX_CIPHER)
            stream.write(b'x')
        with patch.object(recovery, '_age', side_effect=AssertionError('must not decrypt')):
            with self.assertRaises(ReviewError):
                recovery.restore(cipher, self.identity, self.restored, EXPECTED)


if __name__ == '__main__':
    unittest.main()
