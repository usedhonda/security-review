"""Adversarial regressions for the 2026-10-31 public-release review."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from security_review.api import OpenAIClient
from security_review.cli import run_experiment
from security_review.reports import initialize_output
from security_review.safety import ReviewError
from security_review.sources import load_manifest, prepare_case
from test_core import SourceFixture, FakeClient, completed_response


class BillingRegressions(SourceFixture):
    def test_incomplete_selection_is_rejected_before_count_or_generation(self):
        self.case['max_source_bytes'] = len((self.sources/'app.py').read_bytes().splitlines(keepends=True)[0])
        self.write_manifest()
        client = FakeClient()
        result = self.run_live(client)
        self.assertEqual(client.count_calls, 0)
        self.assertEqual(client.generate_calls, 0)
        self.assertEqual(result['status'], 'incomplete')

    def test_different_priced_model_suffix_is_not_accepted(self):
        response = completed_response()
        response['model'] = 'gpt-6.1-sol-pro'
        result = self.run_live(FakeClient(responses=[response]))
        self.assertEqual(result['status'], 'incomplete')
        self.assertIsNone(result['cases'][0]['cost_usd'])

    def test_effective_pro_reasoning_is_not_charged_at_standard_rate(self):
        response = completed_response()
        response['reasoning'] = {'mode': 'pro'}
        result = self.run_live(FakeClient(responses=[response]))
        self.assertEqual(result['status'], 'incomplete')
        self.assertIsNone(result['cases'][0]['cost_usd'])

    def test_missing_service_tier_is_unknown_not_standard(self):
        response = completed_response()
        response.pop('service_tier')
        result = self.run_live(FakeClient(responses=[response]))
        self.assertEqual(result['status'], 'incomplete')
        self.assertIsNone(result['cases'][0]['cost_usd'])

    def test_preflight_unexpected_error_checkpoints_and_stops(self):
        class BrokenCounter(FakeClient):
            def count_tokens(self, payload):
                raise ValueError('DO_NOT_EXPORT_PRIVATE_REQUEST')
        result = self.run_live(BrokenCounter())
        self.assertEqual(result['status'], 'incomplete')
        self.assertNotIn('DO_NOT_EXPORT_PRIVATE_REQUEST', json.dumps(result))
        self.assertEqual(result['budget']['generation_calls_attempted'], 0)


class FilesystemRegressions(SourceFixture):
    def test_ancestor_symlink_cannot_expand_selected_source_root(self):
        (self.root/'alias').symlink_to(self.sources, target_is_directory=True)
        (self.sources/'sub').mkdir()
        (self.sources/'sub'/'app.py').write_text('confidential = 123\n')
        self.case['source_root'] = 'alias/sub'
        with self.assertRaises(ReviewError):
            self.prepare()

    def test_manifest_symlink_is_rejected(self):
        link = self.root/'manifest-link.json'
        link.symlink_to(self.manifest)
        with self.assertRaises(ReviewError):
            load_manifest(link)

    def test_output_directory_is_claimed_before_report_creation(self):
        output = self.root/'reports'
        initialize_output(output)
        with self.assertRaises(ReviewError):
            initialize_output(output)


class AdditionalRegressions(SourceFixture):
    def test_date_snapshot_is_accepted(self):
        response = completed_response()
        response['model'] = 'gpt-6.1-sol-2026-10-28'
        self.assertEqual(self.run_live(FakeClient(responses=[response]))['status'], 'completed')

    def test_missing_effective_reasoning_mode_is_unknown(self):
        response = completed_response()
        response.pop('reasoning')
        result = self.run_live(FakeClient(responses=[response]))
        self.assertEqual(result['status'], 'incomplete')
        self.assertIsNone(result['cases'][0]['cost_usd'])

    def test_invalid_calendar_snapshot_is_not_accepted(self):
        response = completed_response()
        response['model'] = 'gpt-6.1-sol-2026-99-99'
        self.assertEqual(self.run_live(FakeClient(responses=[response]))['status'], 'incomplete')

    def test_manifest_is_bounded_without_path_read_bytes(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('Unbounded read forbidden')):
            self.assertEqual(load_manifest(self.manifest)[0]['id'], 'sample')

    def test_manifest_fifo_is_rejected_without_blocking(self):
        fifo = self.root/'manifest.fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ReviewError):
            load_manifest(fifo)

    def test_oversized_manifest_is_rejected(self):
        self.manifest.write_bytes(b' ' * 256001)
        with self.assertRaises(ReviewError):
            load_manifest(self.manifest)

    def test_boolean_schema_version_is_rejected(self):
        self.manifest.write_text(json.dumps({'schema_version': True, 'cases': [self.case]}))
        with self.assertRaises(ReviewError):
            load_manifest(self.manifest)

    def test_output_ancestor_symlink_is_rejected(self):
        (self.root/'alias').symlink_to(self.sources, target_is_directory=True)
        with self.assertRaises(ReviewError):
            initialize_output(self.root/'alias'/'output')
        self.assertFalse((self.sources/'output').exists())

    def test_duplicate_claim_is_atomic_across_processes(self):
        from concurrent.futures import ProcessPoolExecutor
        output = str(self.root/'parallel')
        with ProcessPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(try_claim, [output, output]))
        self.assertEqual(sorted(results), [False, True])

    def test_http_status_is_retained_without_reflected_error_text(self):
        error = urllib.error.HTTPError('https://api.openai.com/v1/responses/input_tokens',
                                     401, 'error', {}, io.BytesIO(b'private-response-body'))
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-only-key'}), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            result = self.run_live(OpenAIClient())
        case = result['cases'][0]
        self.assertEqual(case['error_http_status'], 401)
        self.assertEqual(case['error_phase'], 'token_count')
        self.assertEqual(result['budget']['generation_calls_attempted'], 0)
        self.assertNotIn('private-response-body', json.dumps(result))
        self.assertNotIn('test-only-key', json.dumps(result))

    def test_report_file_modes_are_private(self):
        self.run_live(FakeClient())
        for name in ('summary.json', 'summary.md', '.run.lock'):
            self.assertEqual((self.root/'reports'/name).stat().st_mode & 0o777, 0o600)


def try_claim(path):
    try:
        initialize_output(Path(path))
        return True
    except ReviewError:
        return False


if __name__ == '__main__':
    unittest.main()
