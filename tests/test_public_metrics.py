"""Protect the boundary between private review details and public summaries."""

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from security_review.public_metrics import main, public_metrics, render_public_summary


def sample_report():
    return {
        "schema_version": 1,
        "status": "completed",
        "configuration": {"model": "gpt-6.1-sol"},
        "budget": {
            "generation_calls_attempted": 1, "max_generation_calls": 3,
            "limit_usd": "1.00", "usage_derived_cost_usd": "0.0022",
            "unresolved_reserved_cost_usd": "0.00", "accounted_cost_usd": "0.0022",
        },
        "token_count_api_requests": 1,
        "cases": [{
            "id": "private-case-id", "repository": "private-owner/private-repo", "commit": "a" * 40,
            "model": "gpt-6.1-sol", "status": "completed",
            "coverage": {
                "requested_files": 1, "included_files": 1, "source_bytes": 500,
                "selected_bytes": 400, "included_bytes": 400,
                "complete_for_selection": True, "selected_byte_fraction": 1.0,
                "files": [{"path": "private/path.py", "included_ranges": [[120, 150]]}],
                "source_lines": 999,
            },
            "usage": {"input_tokens": 100, "output_tokens": 200, "total_tokens": 300, "cached_input_tokens": 0, "reasoning_tokens": 150, "cache_write_tokens": 0, "cache_write_tokens_30m": 0, "cache_write_tokens_12h": 0},
            "estimated_input_tokens": 4000, "preflight_input_tokens": 100,
            "estimated_max_cost_usd": "0.068", "reserved_cost_usd": "0.0602",
            "cost_usd": "0.0022", "cost_status": "calculated_from_api_usage",
            "review": {"summary": "private-model-summary", "findings": [], "limitations": ["private-limitation"]},
        }],
    }


class PublicMetricsTests(unittest.TestCase):
    def test_free_text_paths_findings_and_secret_values_never_reach_public_output(self):
        report = sample_report()
        secret = "sk-private-marker-0123456789"
        report["reason"] = secret
        report["unexpected"] = {"secret": secret}
        report["cases"][0]["reason"] = secret
        report["cases"][0]["review"]["findings"] = [{
            "title": secret, "evidence": "private-exploit-evidence", "fix": "private-fix",
            "file": "private/finding.py", "start_line": 12345, "end_line": 12346,
        }]
        before = deepcopy(report)
        result = public_metrics(report)
        rendered = render_public_summary(report)
        serialized = json.dumps(result)
        for value in (secret, "private-case-id", "private-owner", "private-model-summary", "private-limitation", "private-exploit-evidence", "private-fix", "private/path.py", "private/finding.py", "12345", "12346", "included_ranges", "source_lines"):
            self.assertNotIn(value, serialized)
            self.assertNotIn(value, rendered)
        self.assertEqual(result["cases"][0]["findings_count"], 1)
        self.assertEqual(report, before)  # Full local reports remain intact.

    def test_unknown_usage_cost_and_incomplete_findings_stay_null(self):
        report = sample_report()
        report["status"] = "incomplete"
        report["budget"].update(usage_derived_cost_usd="0.00", unresolved_reserved_cost_usd="0.0602", accounted_cost_usd="0.0602")
        report["cases"][0].update(status="incomplete", usage=None, cost_usd=None, cost_status="reserved_usage_unknown", review={"findings": []})
        result = public_metrics(report)
        self.assertIsNone(result["actual_cost_usd"])
        self.assertIsNone(result["findings_count"])
        self.assertTrue(all(value is None for value in result["usage"].values()))
        self.assertIsNone(result["cases"][0]["usage"])
        self.assertIsNone(result["cases"][0]["findings_count"])
        self.assertEqual(result["known_usage_cost_subtotal_usd"], "0.00000000")
        self.assertEqual(result["unresolved_reserved_cost_usd"], "0.06020000")
        self.assertIn('"actual_cost_usd": null', render_public_summary(report))

    def test_real_zero_findings_and_known_usage_survive_without_inventing_missing_details(self):
        report = sample_report()
        report["cases"][0]["usage"]["cache_write_tokens_12h"] = None
        result = public_metrics(report)
        self.assertEqual(result["findings_count"], 0)
        self.assertEqual(result["actual_cost_usd"], "0.00220000")
        self.assertEqual(result["usage"]["input_tokens"], 100)
        self.assertEqual(result["usage"]["cached_input_tokens"], 0)
        self.assertIsNone(result["usage"]["cache_write_tokens_12h"])

    def test_mixed_known_and_unreviewed_cases_do_not_report_false_totals(self):
        report = sample_report()
        report["status"] = "incomplete"
        report["cases"].append({"status": "skipped_budget", "cost_status": "not_called", "usage": None, "review": None})
        result = public_metrics(report)
        self.assertIsNone(result["actual_cost_usd"])
        self.assertIsNone(result["usage"]["input_tokens"])
        self.assertIsNone(result["findings_count"])
        self.assertEqual(result["cases"][0]["findings_count"], 0)

    def test_only_fixed_statuses_models_and_well_typed_numeric_fields_are_published(self):
        report = sample_report()
        malicious = "private-value | ![x](https://example.invalid/)"
        report["status"] = malicious
        report["configuration"]["model"] = malicious
        report["budget"]["limit_usd"] = malicious
        report["cases"][0].update(status=malicious, model=malicious, cost_status=malicious, cost_usd="0.0")
        report["cases"][0]["coverage"].update(source_bytes=True, selected_bytes=-1, included_bytes=malicious, selected_byte_fraction=float("nan"))
        report["cases"][0]["usage"]["input_tokens"] = malicious
        result = public_metrics(report)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["cases"][0]["status"], "unknown")
        self.assertIsNone(result["model"])
        self.assertIsNone(result["cases"][0]["actual_cost_usd"])
        self.assertIsNone(result["cases"][0]["coverage"]["source_bytes"])
        self.assertIsNone(result["cases"][0]["coverage"]["selected_byte_fraction"])
        self.assertNotIn(malicious, render_public_summary(report))

    def test_missing_or_invalid_reports_produce_fixed_fallback_without_raw_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            for content, outcome, expected in ((None, "skipped", "not_run"), ("private invalid JSON", "failure", "incomplete")):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    self.assertEqual(main([str(path), "--step-outcome", outcome]), 0)
                output = stdout.getvalue()
                self.assertIn(f"Status: **{expected}**", output)
                self.assertIn('"actual_cost_usd": null', output)
                self.assertIn('"findings_count": null', output)
                self.assertNotIn("private invalid JSON", output)
                self.assertNotIn(str(path), output)


if __name__ == "__main__":
    unittest.main()
