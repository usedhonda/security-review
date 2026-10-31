"""Regression assertions for reviewed templates, not a general YAML/security analyzer."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowGuards(unittest.TestCase):
    def test_paid_workflow_remains_manual_and_read_only(self):
        source = (ROOT / '.github/workflows/benchmark.yml').read_text()
        self.assertIn('workflow_dispatch:', source)
        for event in ('push', 'pull_request', 'pull_request_target', 'workflow_run', 'schedule'):
            self.assertNotRegex(source, rf'(?m)^\s*{event}:')
        self.assertIn('contents: read', source)
        self.assertNotRegex(source, r'(?m):\s*write\s*$')
        self.assertNotIn('secrets: inherit', source)
        self.assertLess(source.index('Run offline safety and accounting tests'), source.index('secrets.OPENAI_API_KEY'))
        self.assertLess(source.index('recovery preflight'), source.index('secrets.OPENAI_API_KEY'))
        self.assertIn('persist-credentials: false', source)
        self.assertIn('"$GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH"', source)

    def test_offline_workflow_has_no_openai_secret(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertNotIn('OPENAI_API_KEY', source)
        self.assertNotIn('security_review run', source)
        self.assertIn('unittest discover -s tests -v', source)
        self.assertIn('REQUIRE_AGE: "1"', source)
        self.assertNotIn('upload-artifact', source)

    def test_workflow_actions_are_pinned_to_full_commit(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            for action in re.findall(r'(?m)^\s*-?\s*uses:\s*(\S+)', path.read_text()):
                self.assertRegex(action, r'^[A-Za-z0-9_./-]+@[a-f0-9]{40}$')

    def test_only_fixed_encrypted_file_can_be_uploaded(self):
        source = (ROOT / '.github/workflows/benchmark.yml').read_text()
        upload = source.split('- name: Upload only the encrypted report')[1].split('- name: Publish only')[0]
        self.assertIn("steps.seal.outcome == 'success'", upload)
        self.assertIn("steps.probe.outcome == 'success'", upload)
        self.assertEqual(re.findall(r'(?m)^\s*path: (.+)$', upload), ['${{ runner.temp }}/security-review-encrypted/report.json.age'])
        self.assertIn('if-no-files-found: error', upload)
        self.assertIn('retention-days: 7', upload)
        self.assertIn('include-hidden-files: false', upload)
        self.assertIn('overwrite: false', upload)
        self.assertNotIn('OPENAI_API_KEY', upload)

    def test_default_probe_and_explicit_recovery_confirmation(self):
        source = (ROOT / '.github/workflows/benchmark.yml').read_text()
        self.assertIn('default: recovery-check', source)
        self.assertIn('recovery_confirmed:', source)
        probe = source.split('- name: Create an API-free recovery probe')[1].split('- name: Verify the API secret')[0]
        self.assertIn("inputs.mode == 'recovery-check'", probe)
        self.assertNotIn('OPENAI_API_KEY', probe)
        self.assertIn('seal --probe', probe)
        for name in ('Verify the API secret is configured', 'Fetch pinned public source samples', 'Review the pilot samples'):
            block = source.split('- name: ' + name)[1].split('\n      - name:')[0]
            self.assertIn("inputs.mode == 'review'", block)
