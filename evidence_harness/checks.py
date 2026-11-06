"""Deterministic pass/fail criteria.

Criteria are code and data, never another model's opinion. A case passes or
fails by regex, so the same output always gets the same verdict, today and in
a year. Criteria are hashed and pre-registered before the first call, so they
cannot be adjusted after seeing the results.
"""

import re


def evaluate(case: dict, output: str) -> dict:
    """Return the verdict for one sample, with the exact rule that decided it."""
    hits_forbidden = [p for p in case.get("forbidden", []) if re.search(p, output, re.IGNORECASE)]
    missing_required = [p for p in case.get("required", []) if not re.search(p, output, re.IGNORECASE)]
    passed = not hits_forbidden and not missing_required
    return {
        "passed": passed,
        "matched_forbidden": hits_forbidden,
        "missing_required": missing_required,
    }


def wilson_interval(passes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval. Honest for small samples where a plain
    pass rate (e.g. 10/10 = 100%) overstates what was actually shown."""
    if n == 0:
        return (0.0, 0.0)
    p = passes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))
