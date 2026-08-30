from __future__ import annotations

import hashlib
from importlib.resources import files
import json
import tempfile
import unittest
from pathlib import Path

from threesat_cli.dimacs_parser_core import (
    DEFAULT_DIMACS_RESOURCE_LIMITS,
    DIMACS_PARSER_CORE_VERSION,
    DimacsCnfLineParser,
    InvalidDimacsError,
    ParsedCnf,
    canonical_dimacs_cnf_text,
    decode_dimacs_cnf_bytes,
    encode_dimacs_cnf_text,
    load_dimacs_cnf_file,
    parse_dimacs_cnf_bytes,
    parse_dimacs_cnf_file,
    parse_dimacs_cnf_text,
    resolve_dimacs_resource_limits,
)


CORPUS_RESOURCE = files("threesat_cli").joinpath("data/dimacs-parser-corpus.json")


class DimacsParserCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus_bytes = CORPUS_RESOURCE.read_bytes()
        cls.corpus = json.loads(cls.corpus_bytes.decode("utf-8"))

    def test_packaged_corpus_is_bound_to_the_protocol_profile(self) -> None:
        self.assertEqual(self.corpus["schemaVersion"], 1)
        self.assertEqual(self.corpus["profileVersion"], DIMACS_PARSER_CORE_VERSION)
        self.assertEqual(DIMACS_PARSER_CORE_VERSION, "3sat-dimacs-strict-v1")
        self.assertEqual(
            hashlib.sha256(self.corpus_bytes).hexdigest(),
            "686c59a8b116b2a42ab4996e8d42b1cfd020e61491707e5966264f8e814cb426",
        )

    def test_accepts_every_shared_corpus_fixture_as_text_and_bytes(self) -> None:
        for fixture in self.corpus["valid"]:
            with self.subTest(name=fixture["name"]):
                expected = ParsedCnf(
                    variables=fixture["variables"], clauses=fixture["clauses"]
                )
                self.assertEqual(parse_dimacs_cnf_text(fixture["input"]), expected)
                self.assertEqual(
                    parse_dimacs_cnf_bytes(encode_dimacs_cnf_text(fixture["input"])),
                    expected,
                )

    def test_rejects_every_shared_corpus_fixture_as_text_and_bytes(self) -> None:
        for fixture in self.corpus["invalid"]:
            with self.subTest(name=fixture["name"]):
                with self.assertRaises(InvalidDimacsError):
                    parse_dimacs_cnf_text(fixture["input"])
                with self.assertRaises(InvalidDimacsError):
                    parse_dimacs_cnf_bytes(encode_dimacs_cnf_text(fixture["input"]))

    def test_preserves_clause_semantics_and_normalizes_negative_zero(self) -> None:
        self.assertEqual(parse_dimacs_cnf_text("p cnf -0 -0\n"), ParsedCnf(0, []))
        parsed = parse_dimacs_cnf_text("p cnf 2 4\n2 2 -2 0\n0\n1 0\n1 0\n")
        self.assertEqual(
            canonical_dimacs_cnf_text(parsed),
            "p cnf 2 4\n2 2 -2 0\n0\n1 0\n1 0\n",
        )

    def test_enforces_all_resource_limits_at_limit_plus_one(self) -> None:
        self.assertEqual(
            parse_dimacs_cnf_text("p cnf 1 1\n1 0\n", {"max_lines": 2}),
            ParsedCnf(1, [[1]]),
        )
        cases = (
            ("p cnf 1 1\n\n1 0\n", {"max_lines": 2}),
            ("p cnf 0 0\n%\n\n", {"max_lines": 2}),
            ("p cnf 2 0\n", {"max_variables": 1}),
            ("p cnf 1 2\n1 0\n-1 0\n", {"max_clauses": 1}),
            ("p cnf 1 1\n1 -1 0\n", {"max_literal_occurrences": 1}),
            ("p cnf 0 0\n", {"max_input_bytes": 8}),
        )
        for text, limits in cases:
            with self.subTest(limits=limits), self.assertRaises(InvalidDimacsError):
                parse_dimacs_cnf_text(text, limits)

        prefix = "p cnf 0 0\n%\n"
        maximum = 64
        at_limit = prefix + "x" * (maximum - len(prefix))
        self.assertEqual(
            parse_dimacs_cnf_text(at_limit, {"max_input_bytes": maximum}),
            ParsedCnf(0, []),
        )
        with self.assertRaises(InvalidDimacsError):
            parse_dimacs_cnf_text(at_limit + "x", {"max_input_bytes": maximum})

    def test_incremental_parser_requires_one_physical_line(self) -> None:
        clauses: list[list[int]] = []
        parser = DimacsCnfLineParser(on_clause=clauses.append)
        for line in ("c comment", "p cnf 3 2", "1 -2", "3 0 0"):
            parser.push_line(line)
        summary = parser.finish()
        self.assertEqual(clauses, [[1, -2, 3], []])
        self.assertEqual(summary.declared_variables, 3)
        with self.assertRaisesRegex(TypeError, "exactly one physical line"):
            DimacsCnfLineParser().push_line("p cnf 0 0\n")

    def test_long_leading_zeros_are_accepted_but_huge_number_is_bounded(self) -> None:
        zeros = "0" * 10_000
        self.assertEqual(
            parse_dimacs_cnf_text(f"p cnf {zeros}1 1\n{zeros}1 0\n"),
            ParsedCnf(1, [[1]]),
        )
        with self.assertRaises(InvalidDimacsError) as raised:
            parse_dimacs_cnf_text(f"p cnf 1 1\n{'9' * 10_000} 0\n")
        self.assertLess(len(str(raised.exception)), 300)
        self.assertIn("length 10000", str(raised.exception))

    def test_header_rejects_many_extra_fields_without_collecting_them_all(self) -> None:
        with self.assertRaisesRegex(InvalidDimacsError, "header must be"):
            parse_dimacs_cnf_text("p cnf 0 0 " + "x " * 10_000)

    def test_byte_decoder_matches_textdecoder_bom_and_replacement_behavior(self) -> None:
        self.assertEqual(decode_dimacs_cnf_bytes(b"\xef\xbb\xbfp cnf 0 0\n"), "p cnf 0 0\n")
        self.assertEqual(
            parse_dimacs_cnf_bytes(b"p cnf 0 0\n%\n\xff"), ParsedCnf(0, [])
        )
        with self.assertRaises(InvalidDimacsError):
            parse_dimacs_cnf_bytes(b"p cnf 1 1\n\xff 0\n")

    def test_text_encoder_matches_javascript_for_surrogates(self) -> None:
        self.assertEqual(encode_dimacs_cnf_text("\ud800"), b"\xef\xbf\xbd")
        self.assertEqual(encode_dimacs_cnf_text("\ud83d\ude00"), "😀".encode())
        value = "p cnf 0 0\n%\n\ud800"
        self.assertEqual(
            parse_dimacs_cnf_text(value, {"max_input_bytes": 15}),
            ParsedCnf(0, []),
        )
        with self.assertRaises(InvalidDimacsError):
            parse_dimacs_cnf_text(value, {"max_input_bytes": 14})
        astral_value = "p cnf 0 0\n%\n😀"
        self.assertEqual(
            parse_dimacs_cnf_text(astral_value, {"max_input_bytes": 16}),
            ParsedCnf(0, []),
        )
        with self.assertRaises(InvalidDimacsError):
            parse_dimacs_cnf_text(astral_value, {"max_input_bytes": 15})

    def test_file_adapter_bounds_raw_bytes_and_returns_the_exact_payload(self) -> None:
        raw = b"p cnf 0 0\r%\r\xff"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "raw.cnf")
            path.write_bytes(raw)
            payload, parsed = load_dimacs_cnf_file(
                path, {"max_input_bytes": len(raw)}
            )
            self.assertEqual(payload, raw)
            self.assertEqual(parsed, ParsedCnf(0, []))
            self.assertEqual(parse_dimacs_cnf_file(path), ParsedCnf(0, []))
            with self.assertRaises(InvalidDimacsError):
                parse_dimacs_cnf_file(path, {"max_input_bytes": len(raw) - 1})

    def test_limit_configuration_rejects_python_bool_and_above_ceiling(self) -> None:
        for limits in (
            {"max_lines": True},
            {"max_lines": -1},
            {"max_lines": DEFAULT_DIMACS_RESOURCE_LIMITS.max_lines + 1},
        ):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                resolve_dimacs_resource_limits(limits)


if __name__ == "__main__":
    unittest.main()
