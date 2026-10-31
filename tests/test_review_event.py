import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('review_event', Path(__file__).resolve().parents[1] / 'scripts/review_event.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
BASE, HEAD = 'a' * 40, 'b' * 40
REPO = 'alice/example'


def event():
    return {'repository': {'full_name': REPO, 'private': False, 'default_branch': 'main'},
            'number': 7, 'pull_request': {'state': 'open', 'number': 7,
                'user': {'login': 'alice'}, 'base': {'ref': 'main', 'sha': BASE},
                'head': {'sha': HEAD, 'repo': {'full_name': REPO}}}}


def env():
    return {'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_NAME': 'pull_request',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123',
            'GITHUB_TOKEN': 'synthetic', 'OPENAI_API_KEY': 'synthetic'}


def comparison(files):
    return {'base_commit': {'sha': BASE}, 'commits': [{'sha': HEAD}], 'total_commits': 1, 'files': files}


def file_row(path='src/a.py', status='modified', blob='c' * 40):
    return {'filename': path, 'status': status, 'sha': blob}


class Client:
    def __init__(self, replies):
        self.replies = replies
        self.paths = []

    def call(self, path):
        self.paths.append(path)
        return self.replies[path]


class EventTests(unittest.TestCase):
    def test_exact_pr_revisions(self):
        scope = m.event_scope(event(), env())
        self.assertEqual((scope['base'], scope['head'], scope['pr']), (BASE, HEAD, 7))

    def test_push_requires_default_branch(self):
        e = event(); e.update(before=BASE, after=HEAD, ref='refs/heads/main')
        v = env(); v['GITHUB_EVENT_NAME'] = 'push'
        self.assertEqual(m.event_scope(e, v)['pr'], None)
        e['ref'] = 'refs/heads/other'
        with self.assertRaises(m.EventError): m.event_scope(e, v)

    def test_fork_and_non_owner_are_rejected(self):
        e = event(); e['pull_request']['head']['repo']['full_name'] = 'other/fork'
        with self.assertRaises(m.EventError): m.event_scope(e, env())
        e = event(); e['pull_request']['user']['login'] = 'other'
        with self.assertRaises(m.EventError): m.event_scope(e, env())

    def test_private_repo_and_other_events_rejected(self):
        e = event(); e['repository']['private'] = True
        with self.assertRaises(m.EventError): m.event_scope(e, env())
        v = env(); v['GITHUB_EVENT_NAME'] = 'pull_request_target'
        with self.assertRaises(m.EventError): m.event_scope(event(), v)

    def test_rerun_is_not_billed_again(self):
        v = env(); v['GITHUB_RUN_ATTEMPT'] = '2'
        with self.assertRaises(m.EventError): m.event_scope(event(), v)

    def test_invalid_and_zero_revisions_rejected(self):
        for value in ['main', 'b' * 39, '0' * 40]:
            e = event(); e['pull_request']['head']['sha'] = value
            with self.assertRaises(m.EventError): m.event_scope(e, env())

    def test_budget_is_finite_positive_and_capped(self):
        self.assertEqual(m.budget('0.50'), '0.50')
        for value in ['0', '-1', '1.01', 'NaN', 'Infinity', 'no']:
            with self.assertRaises(m.EventError): m.budget(value)

    def test_unsafe_paths_rejected(self):
        for path in ['../a.py', '/a.py', 'a//b.py', 'a\\b.py', 'a\n.py']:
            with self.assertRaises(m.EventError): m.safe_path(path)

    def test_credentials_and_generated_sources_excluded(self):
        for path in ['.env', 'auth.json', 'x/credentials.json', 'node_modules/a.py', 'x/a.pem', 'dist/a.js']:
            self.assertFalse(m.supported(path))
        self.assertTrue(m.supported('requirements.txt'))
        self.assertTrue(m.supported('.github/workflows/a.yml'))

    def test_docs_only_is_explicitly_not_an_ai_review(self):
        selected, ignored = m.changed_source(m.event_scope(event(), env()), comparison([file_row('README.md')]))
        self.assertEqual((selected, ignored), ([], 1))

    def test_only_changed_source_is_selected(self):
        selected, ignored = m.changed_source(m.event_scope(event(), env()), comparison([file_row(), file_row('README.md')]))
        self.assertEqual([x['path'] for x in selected], ['src/a.py'])
        self.assertEqual(ignored, 1)

    def test_deletions_and_truncation_never_look_clean(self):
        scope = m.event_scope(event(), env())
        for data in [comparison([file_row(status='removed')]),
                     comparison([file_row(str(i) + '.py') for i in range(17)]),
                     comparison([file_row('x' + str(i) + '.md') for i in range(300)])]:
            with self.assertRaises(m.EventError): m.changed_source(scope, data)

    def test_comparison_sha_and_commit_limits(self):
        scope = m.event_scope(event(), env())
        for key, val in [('base_commit', {'sha': HEAD}), ('total_commits', 251)]:
            data = comparison([file_row()]); data[key] = val
            with self.assertRaises(m.EventError): m.changed_source(scope, data)

    def test_downloaded_source_is_pinned_without_execution(self):
        data = b'raise RuntimeError("must never be executed")\n'
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        root = '/repos/' + REPO
        responses = {
            root + '/compare/' + BASE + '...' + HEAD: (200, comparison([file_row(blob=blob)])),
            root + '/git/trees/' + HEAD + '?recursive=1': (200, {'truncated': False, 'tree': [
                {'path': 'src/a.py', 'type': 'blob', 'mode': '100644', 'size': len(data), 'sha': blob}]}),
            root + '/git/blobs/' + blob: (200, {'encoding': 'base64', 'content': base64.b64encode(data).decode()})}
        with tempfile.TemporaryDirectory() as d:
            manifest, coverage = m.collect(Client(responses), m.event_scope(event(), env()), Path(d))
            case = json.loads(manifest.read_text())['cases'][0]
            self.assertEqual(case['commit'], HEAD)
            self.assertEqual(coverage['bytes'], len(data))
            self.assertEqual((Path(d) / 'source/src/a.py').read_bytes(), data)

    def test_symlink_and_size_limit_stop_before_blob_download(self):
        root = '/repos/' + REPO
        for mode, size in [('120000', 10), ('100644', m.MAX_BYTES + 1)]:
            client = Client({root + '/compare/' + BASE + '...' + HEAD: (200, comparison([file_row()])),
                root + '/git/trees/' + HEAD + '?recursive=1': (200, {'truncated': False, 'tree': [
                    {'path': 'src/a.py', 'type': 'blob', 'mode': mode, 'size': size, 'sha': 'c' * 40}]})})
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(m.EventError): m.collect(client, m.event_scope(event(), env()), Path(d))
            self.assertFalse(any('/git/blobs/' in x for x in client.paths))

    def test_stale_pr_cannot_overwrite_latest_verdict(self):
        client = Client({'/repos/' + REPO + '/pulls/7': (200, {'state': 'open', 'head': {'sha': 'd' * 40}, 'base': {'sha': BASE}})})
        with self.assertRaises(m.EventError): m.current_anchor(client, m.event_scope(event(), env()))


class EngineReuseTests(unittest.TestCase):
    def invoke(self, status='completed', findings=None, missing=False):
        cli = types.ModuleType('security_review.cli')
        cli.run_experiment = Mock(return_value={'status': status, 'budget': {
            'generation_calls_attempted': 1, 'usage_derived_cost_usd': '0.01'},
            'cases': [{'review': {'findings': findings or []}}]})
        hub = types.ModuleType('hub_check'); hub.Client = Mock(); hub.check = Mock()
        account = types.ModuleType('account_review'); account.upload = Mock()
        account.report_document = Mock(return_value={'runs': [{'tool': {'driver': {}}, 'automationDetails': {}}]})
        modules = {'security_review.cli': cli, 'hub_check': hub, 'account_review': account}
        v = env()
        if missing: v['OPENAI_API_KEY'] = ''
        with patch.dict(sys.modules, modules), patch.object(m, 'current_anchor', return_value=BASE), patch.object(m, 'collect', return_value=(Path('manifest'), {'files': 1, 'bytes': 20, 'ignored': 0})):
            result = m.run(event(), v)
        return result, cli, hub, account

    def test_calls_original_engine_once_with_budget(self):
        (summary, code), cli, hub, account = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(summary['state'], 'reviewed')
        self.assertEqual(cli.run_experiment.call_args.kwargs['max_calls'], 1)
        self.assertEqual(cli.run_experiment.call_args.kwargs['max_cost_usd'], '0.50')
        self.assertTrue(cli.run_experiment.call_args.kwargs['live'])
        hub.check.assert_called_once()
        account.upload.assert_called_once()
        self.assertEqual(account.upload.call_args.args[3], 'refs/heads/main')

    def test_high_confidence_severe_findings_fail_check(self):
        (summary, code), _, _, _ = self.invoke(findings=[{'severity': 'high', 'confidence': 'high'}])
        self.assertEqual(code, 1)
        self.assertEqual(summary['blocking'], 1)

    def test_incomplete_never_publishes_clean(self):
        (summary, code), _, _, account = self.invoke(status='incomplete')
        self.assertEqual(code, 2)
        account.upload.assert_not_called()

    def test_missing_key_fails_without_calling_engine(self):
        with self.assertRaisesRegex(m.EventError, 'openai_key_unavailable'):
            self.invoke(missing=True)


if __name__ == '__main__': unittest.main()
