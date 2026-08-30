from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from web3 import Web3

from .dimacs_parser_core import (
    ParsedCnf,
    encode_dimacs_cnf_text,
    parse_dimacs_cnf_bytes,
    parse_dimacs_cnf_text,
)


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


def parse_token_amount(value: str, decimals: int) -> int:
    try:
        amount = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise ValueError(f"Invalid token amount: {value}") from exc
    if amount <= 0:
        raise ValueError("Token amount must be greater than zero.")
    scale = Decimal(10) ** decimals
    raw = amount * scale
    if raw != raw.to_integral_value():
        raise ValueError(f"Token amount has more than {decimals} decimal places.")
    return int(raw)


def short_address(address: str) -> str:
    return f"{address[:6]}...{address[-4:]}" if len(address) >= 12 else address


def validate_dimacs_cnf(text: str) -> dict[str, Any]:
    payload = encode_dimacs_cnf_text(text)
    parsed = parse_dimacs_cnf_text(text)
    return _dimacs_summary(parsed, payload)


def validate_dimacs_cnf_bytes(payload: bytes) -> dict[str, Any]:
    parsed = parse_dimacs_cnf_bytes(payload)
    return _dimacs_summary(parsed, payload)


def validate_unit_clause_assignment(parsed: ParsedCnf) -> dict[int, bool]:
    assignment: dict[int, bool] = {}
    for clause in parsed.clauses:
        if len(clause) != 1:
            raise ValueError(
                "SAT solution CNF must contain only unit clauses in assignment mode."
            )
        literal = clause[0]
        variable = abs(literal)
        value = literal > 0
        if variable in assignment and assignment[variable] != value:
            raise ValueError(f"Conflicting SAT assignment for variable {variable}.")
        assignment[variable] = value
    return assignment


def _dimacs_summary(parsed: ParsedCnf, payload: bytes) -> dict[str, Any]:
    digest = Web3.keccak(payload).hex()
    if not digest.startswith("0x"):
        digest = f"0x{digest}"
    return {
        "variables": parsed.variables,
        "clauses": len(parsed.clauses),
        "rawDigest": digest,
    }


def normalize_solution_kind(value: str | int | None) -> int:
    text = str(value or "sat").strip().upper().replace("-", "_")
    if text in {"2", "UNSAT", "UNSAT_PROOF"}:
        return 2
    return 1


def normalize_proof_format(value: str | int | None, solution_kind: int) -> int:
    if solution_kind == 1:
        return 0
    text = str(value or "drat").strip().upper().replace("-", "_")
    if text in {"2", "FRAT", "FRAT_XOR"}:
        return 2
    if text in {"3", "LRAT"}:
        return 3
    return 1


def solution_kind_label(value: int) -> str:
    return "UNSAT proof" if value == 2 else "SAT assignment"


def proof_format_label(value: int) -> str:
    return {0: "None", 1: "DRAT", 2: "FRAT", 3: "LRAT"}.get(value, "Unknown")
