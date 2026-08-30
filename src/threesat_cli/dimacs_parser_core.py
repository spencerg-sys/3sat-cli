"""Self-contained Python implementation of the 3SAT strict DIMACS profile.

The protocol grammar is defined by ``3sat-dimacs-strict-v1``.  This module is
the CLI-native counterpart of ``3sat_dimacs_parser_core/src/dimacs-parser-core.ts``;
the CLI never imports that workspace directory at build time or runtime.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any


INT32_MAX = 2_147_483_647
JAVASCRIPT_SAFE_INTEGER_MAX = 9_007_199_254_740_991

DIMACS_PARSER_CORE_VERSION = "3sat-dimacs-strict-v1"


@dataclass(frozen=True, slots=True)
class DimacsResourceLimits:
    max_input_bytes: int = 25 * 1024 * 1024
    max_lines: int = 3_000_000
    max_variables: int = 500_000
    max_clauses: int = 500_000
    max_literal_occurrences: int = 2_000_000


DEFAULT_DIMACS_RESOURCE_LIMITS = DimacsResourceLimits()


@dataclass(frozen=True, slots=True)
class ParsedCnf:
    variables: int
    clauses: list[list[int]]


@dataclass(frozen=True, slots=True)
class DimacsParseSummary:
    declared_variables: int
    declared_clauses: int
    parsed_clauses: int
    literal_occurrences: int


class InvalidDimacsError(ValueError):
    """The input does not conform to the bounded strict DIMACS profile."""


_LIMIT_FIELDS = (
    "max_input_bytes",
    "max_lines",
    "max_variables",
    "max_clauses",
    "max_literal_occurrences",
)

# ECMAScript WhiteSpace and LineTerminator code points used by JavaScript's
# ``trim()``, ``\s`` and ``\S``.  Python's ``str.isspace`` is intentionally not
# used: it includes characters such as U+0085 that JavaScript does not, and it
# excludes U+FEFF, which JavaScript treats as whitespace.
_ECMASCRIPT_WHITESPACE = frozenset(
    {
        "\u0009",
        "\u000b",
        "\u000c",
        "\u0020",
        "\u00a0",
        "\u1680",
        "\u2000",
        "\u2001",
        "\u2002",
        "\u2003",
        "\u2004",
        "\u2005",
        "\u2006",
        "\u2007",
        "\u2008",
        "\u2009",
        "\u200a",
        "\u2028",
        "\u2029",
        "\u202f",
        "\u205f",
        "\u3000",
        "\ufeff",
        "\u000a",
        "\u000d",
    }
)


def _invalid_dimacs(message: str) -> None:
    raise InvalidDimacsError(message)


def _describe_token(token: str) -> str:
    preview = f"{token[:96]}..." if len(token) > 96 else token
    return f"{preview!r} (length {len(token)})"


def _is_safe_integer(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        return False
    return abs(int(value)) <= JAVASCRIPT_SAFE_INTEGER_MAX


def _bounded_resource_limit(name: str, requested: object, ceiling: int) -> int:
    if not _is_safe_integer(requested):
        raise ValueError(
            f"{name} must be a non-negative safe integer no greater than {ceiling}."
        )
    value = int(requested)
    if value < 0 or value > ceiling:
        raise ValueError(
            f"{name} must be a non-negative safe integer no greater than {ceiling}."
        )
    return value


def resolve_dimacs_resource_limits(
    requested: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> DimacsResourceLimits:
    if requested is None:
        return DEFAULT_DIMACS_RESOURCE_LIMITS
    if isinstance(requested, DimacsResourceLimits):
        values: Mapping[str, Any] = {
            field: getattr(requested, field) for field in _LIMIT_FIELDS
        }
    elif isinstance(requested, Mapping):
        values = requested
    else:
        raise TypeError("DIMACS resource limits must be a mapping or DimacsResourceLimits.")

    resolved: dict[str, int] = {}
    for field in _LIMIT_FIELDS:
        ceiling = getattr(DEFAULT_DIMACS_RESOURCE_LIMITS, field)
        value = values[field] if field in values else ceiling
        resolved[field] = _bounded_resource_limit(field, value, ceiling)
    return DimacsResourceLimits(**resolved)


def _trim_ecmascript_whitespace(value: str) -> str:
    start = 0
    end = len(value)
    while start < end and value[start] in _ECMASCRIPT_WHITESPACE:
        start += 1
    while end > start and value[end - 1] in _ECMASCRIPT_WHITESPACE:
        end -= 1
    return value[start:end]


def _iter_ecmascript_tokens(value: str) -> Iterator[str]:
    start: int | None = None
    for index, character in enumerate(value):
        if character in _ECMASCRIPT_WHITESPACE:
            if start is not None:
                yield value[start:index]
                start = None
        elif start is None:
            start = index
    if start is not None:
        yield value[start:]


def _dimacs_lines(value: str) -> Iterator[str]:
    start = 0
    index = 0
    while index < len(value):
        character = value[index]
        if character not in {"\r", "\n"}:
            index += 1
            continue
        yield value[start:index]
        if character == "\r" and index + 1 < len(value) and value[index + 1] == "\n":
            index += 1
        index += 1
        start = index
    if start < len(value):
        yield value[start:]


def _is_marker_line(line: str, marker: str) -> bool:
    return line == marker or (
        line.startswith(marker)
        and len(line) > 1
        and line[1] in _ECMASCRIPT_WHITESPACE
    )


def _parse_decimal_token(token: str, label: str, *, literal: bool) -> int:
    digits = token[1:] if token.startswith("-") else token
    if not digits or any(character < "0" or character > "9" for character in digits):
        kind = "base-10 literal" if literal else "base-10 integer"
        _invalid_dimacs(f"{label} token {_describe_token(token)} must be a {kind}.")
    significant_digits = digits.lstrip("0") or "0"
    # Avoid Python's configurable integer-string conversion limit without
    # rejecting the arbitrarily long leading-zero spellings accepted by JS.
    if len(significant_digits) > 16:
        _invalid_dimacs(
            f"{label} {_describe_token(token)} is outside JavaScript's safe integer range."
        )
    magnitude = int(significant_digits, 10)
    if magnitude > JAVASCRIPT_SAFE_INTEGER_MAX:
        _invalid_dimacs(
            f"{label} {_describe_token(token)} is outside JavaScript's safe integer range."
        )
    value = -magnitude if token.startswith("-") else magnitude
    # Python has only a positive integer zero, matching the TypeScript core's
    # explicit normalization of both ``0`` and ``-0``.
    return 0 if value == 0 else value


class DimacsCnfLineParser:
    """Incremental strict parser accepting exactly one physical line per call."""

    def __init__(
        self,
        requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
        on_clause: Callable[[list[int]], None] | None = None,
    ) -> None:
        self.limits = resolve_dimacs_resource_limits(requested_limits)
        self._on_clause = on_clause
        self._declared_variables: int | None = None
        self._declared_clauses: int | None = None
        self._current_clause: list[int] = []
        self._parsed_clauses = 0
        self._literal_occurrences = 0
        self._line_count = 0
        self._terminated = False
        self._finished = False

    def push_line(self, raw_line: str) -> None:
        if self._finished:
            raise RuntimeError("Cannot feed a DIMACS parser after finish().")
        if not isinstance(raw_line, str):
            raise TypeError("DimacsCnfLineParser.push_line() requires a string.")
        if "\r" in raw_line or "\n" in raw_line:
            raise TypeError(
                "DimacsCnfLineParser.push_line() requires exactly one physical line."
            )

        self._line_count += 1
        if self._line_count > self.limits.max_lines:
            _invalid_dimacs(
                f"DIMACS input exceeds the {self.limits.max_lines}-line resource limit."
            )
        if self._terminated:
            return

        line = _trim_ecmascript_whitespace(raw_line)
        if not line or _is_marker_line(line, "c"):
            return
        if _is_marker_line(line, "%"):
            self._terminated = True
            return
        if _is_marker_line(line, "p"):
            parts: list[str] = []
            for part in _iter_ecmascript_tokens(line):
                parts.append(part)
                if len(parts) > 4:
                    _invalid_dimacs(
                        "DIMACS header must be p cnf <variables> <clauses>."
                    )
            if (
                self._declared_variables is not None
                or len(parts) != 4
                or parts[0] != "p"
                or parts[1].lower() != "cnf"
            ):
                _invalid_dimacs("DIMACS header must be p cnf <variables> <clauses>.")

            parsed_variables = _parse_decimal_token(
                parts[2], "DIMACS variable count", literal=False
            )
            parsed_clauses = _parse_decimal_token(
                parts[3], "DIMACS clause count", literal=False
            )
            if (
                parsed_variables < 0
                or parsed_clauses < 0
                or parsed_variables > INT32_MAX
                or parsed_clauses > INT32_MAX
            ):
                _invalid_dimacs(
                    "DIMACS header counts must be in the signed 32-bit checker range."
                )
            if (
                parsed_variables > self.limits.max_variables
                or parsed_clauses > self.limits.max_clauses
            ):
                _invalid_dimacs(
                    "DIMACS header exceeds verifier resource limits "
                    f"({self.limits.max_variables} variables, "
                    f"{self.limits.max_clauses} clauses)."
                )
            self._declared_variables = parsed_variables
            self._declared_clauses = parsed_clauses
            return

        if self._declared_variables is None:
            _invalid_dimacs("DIMACS clauses must appear after the problem header.")

        for token in _iter_ecmascript_tokens(line):
            literal = _parse_decimal_token(token, "DIMACS token", literal=True)
            if literal == 0:
                if self._parsed_clauses >= self.limits.max_clauses:
                    _invalid_dimacs(
                        "DIMACS input exceeds the "
                        f"{self.limits.max_clauses}-clause resource limit."
                    )
                completed_clause = self._current_clause
                self._current_clause = []
                self._parsed_clauses += 1
                if self._on_clause is not None:
                    self._on_clause(completed_clause)
                continue

            if abs(literal) > self._declared_variables:
                _invalid_dimacs(
                    f"DIMACS literal {literal} exceeds the declared variable count."
                )
            self._literal_occurrences += 1
            if self._literal_occurrences > self.limits.max_literal_occurrences:
                _invalid_dimacs(
                    "DIMACS input exceeds the "
                    f"{self.limits.max_literal_occurrences}-literal resource limit."
                )
            self._current_clause.append(literal)

    def finish(self) -> DimacsParseSummary:
        if self._finished:
            raise RuntimeError("Cannot finish a DIMACS parser more than once.")
        self._finished = True

        if self._current_clause:
            _invalid_dimacs("Every DIMACS clause must be terminated by 0.")
        if self._declared_variables is None or self._declared_clauses is None:
            _invalid_dimacs("DIMACS file is missing a problem header.")
        if self._parsed_clauses != self._declared_clauses:
            _invalid_dimacs(
                "DIMACS clause count mismatch: header declares "
                f"{self._declared_clauses}, parsed {self._parsed_clauses}."
            )
        return DimacsParseSummary(
            declared_variables=self._declared_variables,
            declared_clauses=self._declared_clauses,
            parsed_clauses=self._parsed_clauses,
            literal_occurrences=self._literal_occurrences,
        )


def encode_dimacs_cnf_text(value: str) -> bytes:
    """Encode exactly like JavaScript ``TextEncoder``/``Buffer.from(..., 'utf8')``."""

    if not isinstance(value, str):
        raise TypeError("DIMACS text input must be a string.")
    output = bytearray()
    index = 0
    while index < len(value):
        code_point = ord(value[index])
        if 0xD800 <= code_point <= 0xDBFF and index + 1 < len(value):
            low = ord(value[index + 1])
            if 0xDC00 <= low <= 0xDFFF:
                combined = 0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00)
                output.extend(chr(combined).encode("utf-8"))
                index += 2
                continue
        if 0xD800 <= code_point <= 0xDFFF:
            output.extend(b"\xef\xbf\xbd")
        else:
            output.extend(value[index].encode("utf-8"))
        index += 1
    return bytes(output)


def _exceeds_utf8_byte_limit(value: str, maximum_bytes: int) -> bool:
    if not isinstance(value, str):
        raise TypeError("DIMACS text input must be a string.")
    total_bytes = 0
    index = 0
    while index < len(value):
        code_point = ord(value[index])
        if code_point <= 0x7F:
            total_bytes += 1
        elif code_point <= 0x7FF:
            total_bytes += 2
        elif 0xD800 <= code_point <= 0xDBFF and index + 1 < len(value):
            low = ord(value[index + 1])
            if 0xDC00 <= low <= 0xDFFF:
                total_bytes += 4
                index += 1
            else:
                total_bytes += 3
        elif 0xD800 <= code_point <= 0xDFFF:
            total_bytes += 3
        elif code_point <= 0xFFFF:
            total_bytes += 3
        else:
            # A Python scalar above U+FFFF is represented by a UTF-16 surrogate
            # pair inside JavaScript and TextEncoder emits four bytes.
            total_bytes += 4
        if total_bytes > maximum_bytes:
            return True
        index += 1
    return False


def decode_dimacs_cnf_bytes(value: bytes | bytearray | memoryview) -> str:
    """Decode like non-fatal WHATWG ``TextDecoder`` for parser consumption."""

    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("DIMACS byte input must be bytes-like.")
    decoded = bytes(value).decode("utf-8", errors="replace")
    # TextDecoder's default ``ignoreBOM: false`` consumes one leading UTF-8
    # BOM.  A second BOM remains data (and is then handled as JS whitespace).
    return decoded[1:] if decoded.startswith("\ufeff") else decoded


def _parse_dimacs_cnf_decoded_text(
    value: str, limits: DimacsResourceLimits
) -> ParsedCnf:
    clauses: list[list[int]] = []
    parser = DimacsCnfLineParser(limits, clauses.append)
    for line in _dimacs_lines(value):
        parser.push_line(line)
    summary = parser.finish()
    return ParsedCnf(variables=summary.declared_variables, clauses=clauses)


def parse_dimacs_cnf_text(
    value: str,
    requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> ParsedCnf:
    limits = resolve_dimacs_resource_limits(requested_limits)
    if _exceeds_utf8_byte_limit(value, limits.max_input_bytes):
        _invalid_dimacs(
            f"DIMACS input exceeds the {limits.max_input_bytes}-byte resource limit."
        )
    return _parse_dimacs_cnf_decoded_text(value, limits)


def parse_dimacs_cnf_bytes(
    value: bytes | bytearray | memoryview,
    requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> ParsedCnf:
    limits = resolve_dimacs_resource_limits(requested_limits)
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("DIMACS byte input must be bytes-like.")
    input_bytes = value.nbytes if isinstance(value, memoryview) else len(value)
    if input_bytes > limits.max_input_bytes:
        _invalid_dimacs(
            f"DIMACS input exceeds the {limits.max_input_bytes}-byte resource limit."
        )
    raw = bytes(value)
    return _parse_dimacs_cnf_decoded_text(decode_dimacs_cnf_bytes(raw), limits)


def load_dimacs_cnf_file(
    file_path: str | Path,
    requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> tuple[bytes, ParsedCnf]:
    """Read once with a raw-byte hard cap and return those bytes plus the AST."""

    limits = resolve_dimacs_resource_limits(requested_limits)
    chunks: list[bytes] = []
    total_bytes = 0
    with Path(file_path).open("rb") as source:
        while True:
            chunk = source.read(min(1024 * 1024, limits.max_input_bytes + 1 - total_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
            if total_bytes > limits.max_input_bytes:
                _invalid_dimacs(
                    f"DIMACS input exceeds the {limits.max_input_bytes}-byte resource limit."
                )
    payload = b"".join(chunks)
    chunks.clear()
    return payload, parse_dimacs_cnf_bytes(payload, limits)


def read_dimacs_cnf_file_bytes(
    file_path: str | Path,
    requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> bytes:
    payload, _parsed = load_dimacs_cnf_file(file_path, requested_limits)
    return payload


def parse_dimacs_cnf_file(
    file_path: str | Path,
    requested_limits: DimacsResourceLimits | Mapping[str, Any] | None = None,
) -> ParsedCnf:
    _payload, parsed = load_dimacs_cnf_file(file_path, requested_limits)
    return parsed


def canonical_dimacs_cnf_text(value: ParsedCnf) -> str:
    """Serialize without changing parsed clause/literal semantics."""

    lines = [f"p cnf {value.variables} {len(value.clauses)}"]
    for clause in value.clauses:
        lines.append("0" if not clause else f"{' '.join(map(str, clause))} 0")
    return "\n".join(lines) + "\n"
