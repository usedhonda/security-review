"""Reserve worst-case generation cost before sending each billable request."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .safety import ReviewError

PRICING_VERIFIED_DATE = "2026-10-31"
PRICING_SOURCE = "https://developers.openai.com/api/docs/pricing"
PRICES = {
    "gpt-6.1-sol": {"input": Decimal("2"), "output": Decimal("10"), "cached_input": Decimal("0.1")},
    "gpt-6-astra": {"input": Decimal("10"), "output": Decimal("50"), "cached_input": Decimal("1")},
}
MILLION = Decimal("1000000")


def usd(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.00000001")), "f")


def parse_budget(value: str) -> Decimal:
    try:
        budget = Decimal(value)
    except (InvalidOperation, ValueError):
        raise ReviewError("Budget must be a number between 0 and 1.00 USD.") from None
    if not budget.is_finite() or budget <= 0 or budget > Decimal("1.00"):
        raise ReviewError("This pilot enforces a positive budget of at most 1.00 USD per run.")
    return budget


def pricing(model: str) -> dict[str, Any]:
    if model not in PRICES:
        raise ReviewError("Model is not in the pilot pricing allowlist.")
    return {"currency": "USD", "unit": "per_million_tokens", "service_tier": "standard", "reasoning_mode": "standard", "input": str(PRICES[model]["input"]), "output": str(PRICES[model]["output"]), "cached_input": str(PRICES[model]["cached_input"]), "cache_write_30m_multiplier": "1.25", "cache_write_12h_multiplier": "2.5", "cache_mode": "disabled_explicit_without_breakpoints", "cache_pricing_source": "https://developers.openai.com/api/docs/guides/prompt-caching", "verified_date": PRICING_VERIFIED_DATE, "source": PRICING_SOURCE, "maximum_input_tokens": 128_000}


def cost(model: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, cache_write_tokens_30m: int = 0, cache_write_tokens_12h: int = 0) -> Decimal:
    if model not in PRICES or any(type(value) is not int or value < 0 for value in (input_tokens, output_tokens, cached_tokens, cache_write_tokens_30m, cache_write_tokens_12h)) or cached_tokens + cache_write_tokens_30m + cache_write_tokens_12h > input_tokens:
        raise ReviewError("Invalid model or token usage for cost calculation.")
    price = PRICES[model]
    ordinary = input_tokens - cached_tokens - cache_write_tokens_30m - cache_write_tokens_12h
    return (ordinary * price["input"] + cached_tokens * price["cached_input"] + cache_write_tokens_30m * price["input"] * Decimal("1.25") + cache_write_tokens_12h * price["input"] * Decimal("2.5") + output_tokens * price["output"]) / MILLION


class Budget:
    def __init__(self, limit: Decimal, max_calls: int) -> None:
        self.limit = limit
        self.max_calls = max_calls
        self.attempted_calls = 0
        self.measured = Decimal(0)
        self.unresolved = Decimal(0)
        self._pending: dict[str, Decimal] = {}

    @property
    def accounted(self) -> Decimal:
        return self.measured + self.unresolved

    def reserve(self, case_id: str, amount: Decimal) -> bool:
        if case_id in self._pending or amount < 0:
            raise ReviewError("Invalid cost reservation.")
        if self.attempted_calls >= self.max_calls or self.accounted + amount > self.limit:
            return False
        self._pending[case_id] = amount
        self.unresolved += amount
        self.attempted_calls += 1
        return True

    def settle(self, case_id: str, measured: Decimal | None) -> bool:
        reserved = self._pending.pop(case_id)
        if measured is None:
            return False
        self.unresolved -= reserved
        self.measured += measured
        return measured <= reserved and self.accounted <= self.limit

    def report(self) -> dict[str, Any]:
        return {"limit_usd": usd(self.limit), "max_generation_calls": self.max_calls, "generation_calls_attempted": self.attempted_calls, "usage_derived_cost_usd": usd(self.measured), "unresolved_reserved_cost_usd": usd(self.unresolved), "accounted_cost_usd": usd(self.accounted), "remaining_budget_usd": usd(max(Decimal(0), self.limit - self.accounted)), "automatic_retries": 0, "scope": "one_cli_run; not_account_wide", "basis": "published_rates; not_invoice_or_credit_balance"}
