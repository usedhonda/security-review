"""Input/output hygiene. This is a backstop, not a secret-scanning product."""

from __future__ import annotations

import re
from typing import Any


class ReviewError(Exception):
    """A fixed, safe-to-display error message with no request/response content."""


class Redactor:
    """Redact recognizable credentials and remember their exact values in memory.

    Newline counts are preserved so source line references remain meaningful.
    Values are never written into the report, exceptions, or diagnostic output.
    """

    _patterns = (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    )
    _assignment = re.compile(
        r"(?i)(\b(?:[A-Za-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|secret[_-]?key|private[_-]?key))\b\s*[\"']?\s*[:=]\s*)([\"'])([^\r\n\"']{4,})([\"'])"
    )
    _bearer = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/-]{16,}=*)")
    _url_password = re.compile(r"(https?://[^\s/:@]+:)([^\s/@]+)(@)")

    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self.redactions = 0

    def _hide(self, value: str) -> str:
        if "[REDACTED]" in value:
            return value
        self._secrets.add(value)
        self.redactions += 1
        return "\n".join(["[REDACTED]"] * (value.count("\n") + 1))

    def text(self, value: str) -> str:
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in value:
                value = value.replace(secret, "\n".join(["[REDACTED]"] * (secret.count("\n") + 1)))
        for pattern in self._patterns:
            value = pattern.sub(lambda match: self._hide(match.group()), value)
        value = self._assignment.sub(
            lambda m: m.group(1) + m.group(2) + self._hide(m.group(3)) + m.group(4), value
        )
        value = self._bearer.sub(lambda m: m.group(1) + self._hide(m.group(2)), value)
        return self._url_password.sub(lambda m: m.group(1) + self._hide(m.group(2)) + m.group(3), value)

    def object(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.object(item) for item in value]
        if isinstance(value, dict):
            return {key: self.object(item) for key, item in value.items()}
        return value


def safe_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReviewError(f"Invalid {label}.")
    return value
