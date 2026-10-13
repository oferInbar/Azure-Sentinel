from __future__ import annotations

import re
from typing import Any


def iso_duration(value: Any, default: str = "PT1H") -> tuple[str, str | None]:
    text = str(value or "").strip().lower()
    iso = text.upper()
    if re.fullmatch(
        r"P(?:(?:\d+D)(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?|T(?:\d+H)?(?:\d+M)?(?:\d+S)?)",
        iso,
    ):
        return iso, None
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if not match:
        return default, f"unrecognized queryFrequency {value!r}; defaulted to {default}"
    amount, unit = match.groups()
    return {
        "s": f"PT{amount}S",
        "m": f"PT{amount}M",
        "h": f"PT{amount}H",
        "d": f"P{amount}D",
    }[unit], None
