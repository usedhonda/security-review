"""Regression assertions for this pilot's small, reviewed workflow templates.

These are not a YAML analyzer or a defense against a malicious maintainer.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowGuards(unittest.TestCase):
    def test_paid_workflow_remains_manual_and_read_only(self):
        source = (ROOT/'.github/workflows/benchmark.yml').read_text()
        self.assertIn('workflow_dispatch:', source)
        for event in ('push', 'pull_request', 'pull_request_target', 'workflow_run', 'schedule'):
            self.assertNotRegex(source, rf'(?m)^\s*{event}:')
        self.assertIn('contents: read', source)
        self.assertNotRegex(source, r'(?m):\s*write\s*$')
        self.assertNotIn('secrets: inherit', source)
        self.assertNotIn('upload-artifact', source)
        self.assertLess(source.index('Run offline safety and accounting tests'), source.index('secrets.OPENAI_API_KEY'))
        self.assertIn('persist-credentials: false', source)
        self.assertIn('"$GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH"', source)

    def test_offline_workflow_has_no_openai_secret(self):
        source = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertNotIn('OPENAI_API_KEY', source)
        self.assertNotIn('security_review run', source)
        self.assertIn('unittest discover -s tests -v', source)

    def test_workflow_actions_are_pinned_to_full_commit(self):
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            for action in re.findall(r'(?m)^\s*-?\s*uses:\s*(\S+)', path.read_text()):
                self.assertRegex(action, r'^[A-Za-z0-9_./-]+@[a-f0-9]{40}$')
