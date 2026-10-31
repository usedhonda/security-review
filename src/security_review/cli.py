"""Command line entry point; plan is offline and run is explicitly billable."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from .api import MAX_INPUT_TOKENS, OpenAIClient, build_request, offline_token_bound, parse_review, parse_usage
from .budget import Budget, PRICES, cost, parse_budget, pricing, usd
from .reports import initialize_output, sanitized_report, write_reports
from .safety import Redactor, ReviewError, safe_integer
from .sources import load_manifest, prepare_case
from .guards import billing_matches, http_status


def run_experiment(
    manifest: Path,
    output_dir: Path,
    *,
    live: bool = False,
    model: str = "gpt-6.1-sol",
    max_cost_usd: str = "1.00",
    max_calls: int = 3,
    max_output_tokens: int = 6000,
    client: Any = None,
) -> dict[str, Any]:
    """Prepare all cases before spending; supplied client is for offline tests."""
    rate_card = pricing(model)
    limit = parse_budget(max_cost_usd)
    safe_integer(max_calls, "max_calls", 1, 3)
    safe_integer(max_output_tokens, "max_output_tokens", 128, 6000)
    cases = load_manifest(manifest)
    redactor = Redactor()
    prepared_cases = [prepare_case(case, manifest.resolve().parent, redactor) for case in cases]
    initialize_output(output_dir)
    budget = Budget(limit, max_calls)
    report: dict[str, Any] = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "in_progress" if live else "planned",
        "mode": "live" if live else "offline_plan",
        "pricing": rate_card,
        "configuration": {"model": model, "max_output_tokens": max_output_tokens, "reasoning_effort": "low", "reasoning_mode": "standard", "store": False, "tools": [], "prompt_cache_options": {"mode": "explicit"}, "prompt_cache_breakpoints": 0, "code_execution": False, "max_input_tokens": MAX_INPUT_TOKENS, "token_counting": "required_official_preflight_for_live; offline_byte_estimate_for_plan"},
        "token_count_api_requests": 0,
        "budget": budget.report(),
        "cases": [],
    }
    requests = []
    for prepared in prepared_cases:
        request = build_request(prepared, model, max_output_tokens)
        requests.append(request)
        estimate = offline_token_bound(request)
        result = {
            **prepared["public"],
            "model": model,
            "status": "pending" if live else "planned",
            "estimated_input_tokens": estimate,
            "estimate_method": "utf8_payload_bytes_plus_4096; planning_only",
            "estimated_max_cost_usd": usd(cost(model, estimate, max_output_tokens)),
            "preflight_input_tokens": None,
            "reserved_cost_usd": None,
            "usage": None,
            "cost_usd": None,
            "cost_status": "not_called",
            "review": None,
        }
        if not result["coverage"]["included_lines"]:
            result.update(status="skipped_empty", reason="no_source_lines_in_scope")
        report["cases"].append(result)

    def checkpoint() -> None:
        report["budget"] = budget.report()
        write_reports(output_dir, report, redactor)

    checkpoint()
    if not live:
        return sanitized_report(report, redactor)
    # Never pay to review a selection we already know was truncated/excluded.
    if any(not item["coverage"]["complete_for_selection"] for item in report["cases"]):
        report["status"] = "incomplete"
        for item in report["cases"]:
            item.update(status="not_started", reason="incomplete_source_coverage" if not item["coverage"]["complete_for_selection"] else "another_case_has_incomplete_source_coverage")
        checkpoint()
        return sanitized_report(report, redactor)
    if client is None:
        try:
            client = OpenAIClient()
        except ReviewError:
            report["status"] = "incomplete"
            for result in report["cases"]:
                if result["status"] == "pending":
                    result.update(status="not_started", reason="OPENAI_API_KEY_not_configured")
            checkpoint()
            return sanitized_report(report, redactor)

    stop = False
    for request, result in zip(requests, report["cases"]):
        if result["status"] != "pending":
            continue
        if stop:
            result.update(status="skipped_prior_error", reason="run_stopped_after_incomplete_or_unknown_billing")
            continue
        if budget.attempted_calls >= max_calls:
            result.update(status="skipped_call_limit", reason="generation_call_limit")
            continue
        try:
            report["token_count_api_requests"] += 1
            input_tokens = client.count_tokens(request)
            safe_integer(input_tokens, "preflight input token count", 0, 10_000_000)
            result["preflight_input_tokens"] = input_tokens
        except (Exception, KeyboardInterrupt) as error:
            result.update(status="preflight_failed", reason="official_token_count_unavailable; generation_not_sent", error_http_status=http_status(error), error_phase="token_count")
            stop = True
            checkpoint()
            continue
        if input_tokens > MAX_INPUT_TOKENS:
            result.update(status="skipped_input_limit", reason="input_exceeds_pilot_short_context_limit")
            continue
        reserved = cost(model, input_tokens, max_output_tokens)
        if not budget.reserve(result["id"], reserved):
            result.update(status="skipped_budget", reason="remaining_budget_below_worst_case_reservation")
            continue
        result.update(status="in_progress", reserved_cost_usd=usd(reserved), cost_status="reserved_usage_unknown")
        # Persist the reservation before sending. If the process is killed after
        # this point, the report remains explicitly unresolved, never $0/clean.
        checkpoint()
        try:
            response = client.create_response(request)
            if not isinstance(response, dict):
                raise ReviewError("Invalid response object.")
            billing_known = billing_matches(response, model)
            result["response_model"] = response.get("model") if billing_known else None
            result["service_tier"] = response.get("service_tier") if billing_known else None
            result["response_reasoning_mode"] = "standard" if billing_known else None
            usage = parse_usage(response)
            result["usage"] = usage
            measured = None
            cache_usage_known = usage is not None and all(usage[key] is not None for key in ("cached_input_tokens", "cache_write_tokens", "cache_write_tokens_30m", "cache_write_tokens_12h"))
            if usage is not None and cache_usage_known and billing_known:
                measured = cost(model, usage["input_tokens"], usage["output_tokens"], usage["cached_input_tokens"], usage["cache_write_tokens_30m"], usage["cache_write_tokens_12h"])
                result["cost_usd"] = usd(measured)
                result["cost_status"] = "calculated_from_api_usage"
            within_reservation = budget.settle(result["id"], measured)
            status, review, reason = parse_review(response, result["coverage"])
            result.update(status=status, review=redactor.object(review), reason=reason)
            if usage is None or not cache_usage_known or not billing_known:
                result.update(status="incomplete", reason="usage_or_billing_configuration_unknown", cost_status="reserved_usage_unknown")
                stop = True
            elif not within_reservation or usage["input_tokens"] > input_tokens or usage["output_tokens"] > max_output_tokens:
                result.update(status="incomplete", reason="usage_exceeded_preflight_or_reservation")
                stop = True
            elif usage["cached_input_tokens"] or usage["cache_write_tokens"]:
                result.update(status="incomplete", reason="unexpected_cache_activity_despite_explicit_mode_without_breakpoints")
                stop = True
            elif status != "completed":
                stop = True
            elif review is not None:
                sent = {item["path"] for item in result["coverage"]["files"] if item["included_lines"]}
                complete = set(review["reviewed_files"]) == sent
                result["model_reported_all_sent_files"] = complete
                if not complete:
                    result.update(status="incomplete", reason="model_did_not_report_all_sent_files")
                    stop = True
                elif not result["coverage"]["complete_for_selection"]:
                    result.update(status="incomplete", reason="incomplete_source_coverage")
                    stop = True
        except (ReviewError, KeyboardInterrupt) as error:
            result.update(error_http_status=http_status(error), error_phase="generation")
            # Do not refund an ambiguous request or retry it automatically.
            result.update(status="failed", reason="generation_failed; billing_unknown; no_retry", cost_status="reserved_usage_unknown")
            stop = True
        except Exception:
            # Avoid traceback/request data leakage in CI. The pre-send checkpoint
            # already contains the full reservation for unforeseen failures.
            result.update(status="failed", reason="unexpected_processing_failure; no_retry")
            stop = True
        checkpoint()
    report["status"] = "completed" if all(case["status"] == "completed" for case in report["cases"]) else "incomplete"
    checkpoint()
    return sanitized_report(report, redactor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Bounded security review experiments for pinned public code.")
    commands = result.add_subparsers(dest="command", required=True)
    for name, help_text in (("plan", "Measure selected source and estimate cost offline; no API key needed."), ("run", "Make at most three paid Responses API calls with preflight budget reservations.")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--output-dir", type=Path, required=True)
        command.add_argument("--model", choices=list(PRICES), default="gpt-6.1-sol")
        command.add_argument("--max-cost-usd", default="1.00")
        command.add_argument("--max-calls", type=int, default=3)
        command.add_argument("--max-output-tokens", type=int, default=6000)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        report = run_experiment(args.manifest, args.output_dir, live=args.command == "run", model=args.model, max_cost_usd=args.max_cost_usd, max_calls=args.max_calls, max_output_tokens=args.max_output_tokens)
    except ReviewError as error:
        print("security-review: " + str(error), file=sys.stderr)
        return 2
    except (OSError, KeyboardInterrupt):
        print("security-review: interrupted or local I/O failed; inspect the saved summary before retrying.", file=sys.stderr)
        return 2
    except Exception:
        print("security-review: unexpected error; inspect the saved summary before retrying.", file=sys.stderr)
        return 2
    print(f"{report['status']}: {report['budget']['generation_calls_attempted']} generation calls; usage-derived USD {report['budget']['usage_derived_cost_usd']}; reserved unresolved USD {report['budget']['unresolved_reserved_cost_usd']}.")
    for case in report["cases"]:
        status = case.get("error_http_status")
        phase = case.get("error_phase")
        if type(status) is int and 100 <= status <= 599 and phase in {"token_count", "generation"}:
            print(f"API diagnostic: phase={phase}, HTTP {status}; no response body logged and no retry made.")
    print("Reports written: summary.json and summary.md.")
    return 0 if report["status"] in {"planned", "completed"} else 2
