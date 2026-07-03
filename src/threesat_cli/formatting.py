from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def read_text_file(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_bytes(path: str | Path, payload: bytes) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


def filename_from_content_disposition(header: str | None, fallback: str) -> str:
    if not header:
        return fallback
    match = re.search(r'filename="?([^";]+)"?', header)
    return match.group(1) if match else fallback


def format_token_amount(value: int | str, decimals: int, symbol: str) -> str:
    raw = int(value)
    scale = 10**decimals
    whole = raw // scale
    fraction = raw % scale
    if fraction == 0:
        return f"{whole} {symbol}"
    frac = str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{whole}.{frac} {symbol}"


def short_address(address: str) -> str:
    return f"{address[:6]}...{address[-4:]}" if len(address) >= 12 else address

