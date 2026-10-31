"""Publish numeric pilot metrics without disclosing model-written findings."""

from __future__ import annotations

import argparse
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

MAX_REPORT_BYTES = 2_000_000
MODELS = frozenset({"gpt-6.1-sol", "gpt-6-astra"})
RUN_STATUSES = frozenset({"planned", "completed", "incomplete", "not_run"})
CASE_STATUSES = frozenset({
    "planned", "pending", "in_progress", "completed", "incomplete", "failed",
    "not_started", "preflight_failed", "invalid_output", "refused", "skipped_empty",
    "skipped_prior_error", "skipped_call_limit", "skipped_input_limit", "skipped_budget",
})
COST_STATUSES = frozenset({"not_called", "reserved_usage_unknown", "calculated_from_api_usage"})
USAGE_FIELDS = (
    "input_tokens", "output_tokens", "total_tokens", "cached_input_tokens",
    "reasoning_tokens", "cache_write_tokens", "cache_write_tokens_30m", "cache_write_tokens_12h",
)
COVERAGE_FIELDS = ("requested_files", "included_files", "source_bytes", "selected_bytes", "included_bytes")


def _object(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _known(value: Any, allowed: frozenset[str], default: Any = None) -> Any:
    return value if isinstance(value, str) and value in allowed else default


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 1_000_000_000 else None


def _money(value: Any) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,8})?", value):
        return None
    return format(Decimal(value).quantize(Decimal("0.00000001")), "f")


def _fraction(value: Any) -> float | None:
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
        return None
    return round(float(value), 6)


def _known_sum(values: list[Any], *, money: bool = False) -> Any:
    if not values or any(value is None for value in values):
        return None
    if money:
        return format(sum((Decimal(value) for value in values), Decimal(0)), ".8f")
    return sum(values)


def public_metrics(report: Any, *, step_outcome: str = "unknown") -> dict[str, Any]:
    """Construct a new allowlisted object; never copy free text or identifiers."""
    source = _object(report)
    if type(source.get("schema_version")) is not int or source.get("schema_version") != 1:
        source = {}
    fallback = "not_run" if step_outcome == "skipped" else "incomplete"
    recorded_status = source.get("status")
    status = fallback if not source else _known(recorded_status, RUN_STATUSES, "unknown")
    if recorded_status == "in_progress":
        status = "incomplete"
    budget = _object(source.get("budget"))
    configuration = _object(source.get("configuration"))
    raw_cases = source.get("cases")
    valid_cases = isinstance(raw_cases, list) and len(raw_cases) <= 12 and all(isinstance(case, dict) for case in raw_cases)
    cases = []
    for number, raw_case in enumerate(raw_cases if valid_cases else [], start=1):
        coverage = _object(raw_case.get("coverage"))
        raw_usage = raw_case.get("usage")
        usage = {field: _count(raw_usage.get(field)) for field in USAGE_FIELDS} if isinstance(raw_usage, dict) else None
        case_status = _known(raw_case.get("status"), CASE_STATUSES, "unknown")
        cost_status = _known(raw_case.get("cost_status"), COST_STATUSES, "unknown")
        review = _object(raw_case.get("review"))
        findings = review.get("findings")
        findings_known = case_status == "completed" and isinstance(findings, list) and len(findings) <= 100 and all(isinstance(finding, dict) for finding in findings)
        cases.append({
            "case_number": number,
            "status": case_status,
            "model": _known(raw_case.get("model"), MODELS),
            "coverage": {
                **{field: _count(coverage.get(field)) for field in COVERAGE_FIELDS},
                "selected_byte_fraction": _fraction(coverage.get("selected_byte_fraction")),
                "complete_for_selection": coverage.get("complete_for_selection") if type(coverage.get("complete_for_selection")) is bool else None,
            },
            "estimated_input_tokens": _count(raw_case.get("estimated_input_tokens")),
            "preflight_input_tokens": _count(raw_case.get("preflight_input_tokens")),
            "estimated_max_cost_usd": _money(raw_case.get("estimated_max_cost_usd")),
            "reserved_cost_usd": _money(raw_case.get("reserved_cost_usd")),
            "usage": usage,
            "actual_cost_usd": _money(raw_case.get("cost_usd")) if cost_status == "calculated_from_api_usage" else None,
            "cost_status": cost_status,
            "findings_count": len(findings) if findings_known else None,
        })
    return {
        "schema_version": 1,
        "status": status,
        "model": _known(configuration.get("model"), MODELS),
        "case_count": len(cases) if valid_cases else None,
        "generation_calls_attempted": _count(budget.get("generation_calls_attempted")),
        "max_generation_calls": _count(budget.get("max_generation_calls")),
        "token_count_api_requests": _count(source.get("token_count_api_requests")),
        "budget_limit_usd": _money(budget.get("limit_usd")),
        "known_usage_cost_subtotal_usd": _money(budget.get("usage_derived_cost_usd")),
        "unresolved_reserved_cost_usd": _money(budget.get("unresolved_reserved_cost_usd")),
        "accounted_cost_usd": _money(budget.get("accounted_cost_usd")),
        "actual_cost_usd": _known_sum([case["actual_cost_usd"] for case in cases], money=True),
        "usage": {
            field: _known_sum([case["usage"].get(field) if case["usage"] is not None else None for case in cases])
            for field in USAGE_FIELDS
        },
        "findings_count": _known_sum([case["findings_count"] for case in cases]),
        "cases": cases,
    }


def render_public_summary(report: Any, *, step_outcome: str = "unknown") -> str:
    metrics = public_metrics(report, step_outcome=step_outcome)
    display = lambda value: "null" if value is None else str(value)
    lines = [
        "# Security review metrics", "",
        f"Status: **{metrics['status']}**", "",
        "Only allowlisted numeric metrics and fixed status labels are published. Full review reports remain local to the runner.", "",
        "`null` means unknown or unavailable; it is not zero. Costs are calculated from API usage and published prices, before credits or taxes.", "",
        "| Case | Status | Selected bytes | Included bytes | Input tokens | Output tokens | Cost (USD) | Findings |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for case in metrics["cases"]:
        coverage = case["coverage"]
        usage = case["usage"] or {}
        values = (case["case_number"], case["status"], coverage["selected_bytes"], coverage["included_bytes"], usage.get("input_tokens"), usage.get("output_tokens"), case["actual_cost_usd"], case["findings_count"])
        lines.append("| " + " | ".join(display(value) for value in values) + " |")
    lines.extend(["", "An incomplete review has no complete findings count. No security conclusion follows from an empty count.", "", "## Numeric record", "", "```json", json.dumps(metrics, ensure_ascii=True, indent=2, allow_nan=False), "```", ""])
    return "\n".join(lines)


def _read_report(path: Path) -> Any:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                return None
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            return None
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--step-outcome", choices=("unknown", "success", "failure", "cancelled", "skipped"), default="unknown")
    args = parser.parse_args(argv)
    print(render_public_summary(_read_report(args.report), step_outcome=args.step_outcome), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
