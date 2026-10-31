"""Export only sanitized metrics and validated findings, never raw responses."""

from __future__ import annotations

from copy import deepcopy
from html import escape
import json
from pathlib import Path
import re
from typing import Any

from .safety import Redactor
from .guards import claim_output, write_report


def markdown_text(value: Any) -> str:
    value = escape(str(value), quote=False)
    value = re.sub(r"[\r\n\t]+", " ", value)
    # Model and repository strings cannot inject Markdown links, images, headings,
    # tables, HTML, or workflow commands into the rendered artifact.
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)


def render_markdown(report: dict[str, Any]) -> str:
    budget = report["budget"]
    lines = ["# Security review experiment", "", f"Status: **{markdown_text(report['status'])}**", "", "AI findings are unverified hypotheses. An empty finding list is not proof of security. Coverage describes selected files and ranges, not the whole repository.", "", f"Generation calls: {budget['generation_calls_attempted']} / {budget['max_generation_calls']}. Usage-derived cost: **${budget['usage_derived_cost_usd']}**. Unresolved reservations: **${budget['unresolved_reserved_cost_usd']}**. Run limit: **${budget['limit_usd']}**.", "", "Costs use the recorded API token usage and published prices, before credits or taxes; they are not an invoice. Reasoning tokens are already included in output tokens and are not charged twice.", "", "| Case | Status | Files sent | Source bytes sent | Lines sent | Input tokens | Output tokens | Cached input | Reasoning | Cost (USD) |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for case in report["cases"]:
        coverage = case["coverage"]
        usage = case.get("usage") or {}
        fields = [case["id"], case["status"], coverage["included_files"], coverage["included_bytes"], coverage["included_lines"], usage.get("input_tokens", "—"), usage.get("output_tokens", "—"), usage.get("cached_input_tokens", "—"), usage.get("reasoning_tokens", "—"), case.get("cost_usd") or "unknown"]
        lines.append("| " + " | ".join(markdown_text(item if item is not None else "unknown") for item in fields) + " |")
    for case in report["cases"]:
        coverage = case["coverage"]
        lines.extend(["", "## " + markdown_text(case["id"]), "", f"Repository: {markdown_text(case['repository'])}. Commit: {markdown_text(case['commit'])}. Mode: {markdown_text(case['mode'])}.", "", f"Model: {markdown_text(case['model'])}. Status: {markdown_text(case['status'])}. Selection coverage: {coverage['included_bytes']} / {coverage['selected_bytes']} bytes; {coverage['included_lines']} / {coverage['selected_lines']} lines. Complete for selection: {str(coverage['complete_for_selection']).lower()}.", ""])
        if case.get("reason"):
            lines.extend(["Reason: " + markdown_text(case["reason"]), ""])
        if case.get("estimated_input_tokens") is not None:
            lines.extend([f"Offline planning estimate: {case['estimated_input_tokens']} input tokens; conservative byte estimate, not an API measurement. Maximum-output planning cost: ${case['estimated_max_cost_usd']}.", ""])
        if case.get("preflight_input_tokens") is not None:
            lines.extend([f"Official preflight count: {case['preflight_input_tokens']} input tokens. Reserved before generation: ${case.get('reserved_cost_usd', '0')}.", ""])
        if case.get("usage") is not None:
            usage = case["usage"]
            lines.extend([f"Cache reads: {usage.get('cached_input_tokens')}; cache writes: {usage.get('cache_write_tokens')} (30m: {usage.get('cache_write_tokens_30m')}, 12h: {usage.get('cache_write_tokens_12h')}). Missing values mean unknown, not zero.", ""])
        review = case.get("review")
        if review:
            lines.extend([markdown_text(review["summary"]), ""])
            if not review["findings"]:
                lines.extend(["No finding was identified in the supplied scope. This is not a guarantee.", ""])
            for number, finding in enumerate(review["findings"], start=1):
                lines.extend([f"### {number}. {markdown_text(finding['title'])}", "", f"Severity: {markdown_text(finding['severity'])}; confidence: {markdown_text(finding['confidence'])}. {markdown_text(finding['file'])}:{finding['start_line']}-{finding['end_line']}.", ""])
                for field, label in (("entry_point", "Entry point"), ("input_flow", "Input flow"), ("evidence", "Evidence"), ("impact", "Impact"), ("fix", "Suggested fix")):
                    lines.extend([f"**{label}:** {markdown_text(finding[field])}", ""])
            if review["limitations"]:
                lines.extend(["### Model-stated limitations", ""] + ["- " + markdown_text(item) for item in review["limitations"]] + [""])
        lines.extend(["### File coverage", "", "| File | Included / selected lines | Status |", "| --- | ---: | --- |"])
        for item in coverage["files"]:
            lines.append(f"| {markdown_text(item['path'])} | {item['included_lines']} / {item['selected_lines']} | {markdown_text(item.get('reason', item['status']))} |")
    lines.extend(["", "## Experiment configuration", "", f"Price verification date: {report['pricing']['verified_date']}. [Published pricing]({report['pricing']['source']}). Standard service tier and reasoning mode; low reasoning effort. No tools, code execution, automatic retry, or stored API response.", "", "Prompt caching is explicitly disabled using explicit mode without breakpoints. Unexpected cache activity or missing cache usage details stops the run. If write usage is reported, its 30-minute / 12-hour cost is calculated at 1.25 / 2.5 times ordinary input, with no double counting.", "", "Input token counting is required before each live generation. Failure stops the run. An interrupted or failed request with unknown usage retains its full cost reservation. The local cap applies to one run; configure a separate project spend limit for aggregate API usage.", "", "Source files and raw API response bodies are not copied into artifacts; model-written text is redacted best effort. Keep artifacts private until findings are reviewed.", ""])
    return "\n".join(lines)


def initialize_output(directory: Path) -> None:
    claim_output(directory)


def _atomic_write(path: Path, content: str) -> None:
    write_report(path, content)


def sanitized_report(report: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    """Sanitize free text without changing trusted statuses, prices, or hashes.

    Repository text may contain a password equal to "completed" or a short hash
    substring. A blanket replacement over serialized reports would corrupt the
    accounting/coverage fields, so only untrusted display text is redacted here.
    """
    sanitized = deepcopy(report)
    for case in sanitized["cases"]:
        case["repository"] = redactor.text(case["repository"])
        if case.get("review") is not None:
            case["review"] = redactor.object(case["review"])
    return sanitized


def write_reports(directory: Path, report: dict[str, Any], redactor: Redactor) -> None:
    sanitized = sanitized_report(report, redactor)
    _atomic_write(directory / "summary.json", json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(directory / "summary.md", render_markdown(sanitized))
