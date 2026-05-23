"""Safety limiters and scope validation.

Prevents runaway scans and ensures targets stay within authorized scope.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class SafetyLimiter:
    """Hard limit on total events emitted per scan.

    Protects against misconfigured tools (e.g., amass with wildcards)
    or unexpectedly large attack surfaces.
    """

    def __init__(self, max_events: int = 500_000):
        self.max_events = max_events
        self._count = 0

    def check(self) -> bool:
        self._count += 1
        if self._count > self.max_events:
            raise RuntimeError(
                f"Scan exceeded safety limit of {self.max_events} events. "
                "Aborting to prevent runaway execution."
            )
        return True

    @property
    def current(self) -> int:
        return self._count


def validate_target(
    target: str, allowed_suffixes: list[str] | None = None
) -> bool:
    """Verify that a target belongs to an authorized scope.

    Args:
        target: Domain or IP string to validate.
        allowed_suffixes: If provided, target must match at least one.
                          If None, any non-empty string with a dot is accepted.
    """
    if not target or "." not in target:
        return False

    allowed = allowed_suffixes or []
    if not allowed:
        return True

    return any(target.endswith(suffix) or suffix in target for suffix in allowed)
