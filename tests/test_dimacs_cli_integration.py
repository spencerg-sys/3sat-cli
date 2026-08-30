from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from web3 import Web3

from threesat_cli.api import ProtocolApi
from threesat_cli.dimacs_parser_core import InvalidDimacsError
from threesat_cli.main import (
    _read_matched_query,
    build_parser,
    command_issue,
    command_search,
    command_standardize,
    command_upload_solution,
)


def protocol_config() -> dict:
    return {
        "api_url": "https://example.test",
        "chain_id": 421614,
        "bounty_manager": "0x2222222222222222222222222222222222222222",
        "tokens": {
            "USDC": {
                "symbol": "USDC",
                "address": "0x1111111111111111111111111111111111111111",
                "decimals": 6,
            }
        },
    }


class DimacsCliIntegrationTests(unittest.TestCase):
    def test_api_standardize_posts_original_bytes_as_multipart(self) -> None:
        payload = b"p cnf 0 0\n%\n\xff"
        response = Mock(
            ok=True,
            status_code=200,
            reason="OK",
            text='{"canonicalText":"p cnf 0 0"}',
            headers={"content-type": "application/json"},
        )
        response.json.return_value = {"canonicalText": "p cnf 0 0"}
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = response

        api.standardize(payload, file_name="query.cnf")

        api.session.post.assert_called_once_with(
            "https://example.test/api/protocol/sdk/cnf/standardize",
            files={"file": ("query.cnf", payload, "text/plain")},
            timeout=120,
        )

    def test_api_search_posts_original_bytes_as_multipart(self) -> None:
        payload = b"\xef\xbb\xbfp cnf 1 1\r\n1 0\r\n"
        response = Mock(
            ok=True,
            status_code=200,
            reason="OK",
            text='{"query":{"rawDigest":"0x01"}}',
            headers={"content-type": "application/json"},
        )
        response.json.return_value = {"query": {"rawDigest": "0x01"}}
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = response

        api.search(payload, file_name="query.cnf")

        api.session.post.assert_called_once_with(
            "https://example.test/api/protocol/search",
            files={"file": ("query.cnf", payload, "text/plain")},
            timeout=120,
        )

    def test_standardize_and_search_validate_raw_bytes_before_api_use(self) -> None:
        payload = b"\xef\xbb\xbfp cnf 1 1\r\n1 0\r\n"
        raw_digest = Web3.keccak(payload).hex()
        raw_digest = raw_digest if raw_digest.startswith("0x") else f"0x{raw_digest}"
        api = Mock()
        api.standardize.return_value = {"ok": True}
        api.search.return_value = {"query": {"rawDigest": raw_digest}}
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "query.cnf")
            path.write_bytes(payload)
            standardize_args = argparse.Namespace(
                cnf=str(path), json=True, output=None, print_text=False
            )
            search_args = argparse.Namespace(cnf=str(path), json=True)
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                redirect_stdout(io.StringIO()),
            ):
                command_standardize(standardize_args)
                command_search(search_args)

        api.standardize.assert_called_once_with(payload, file_name="query.cnf")
        api.search.assert_called_once_with(payload, file_name="query.cnf")

    def test_search_rejects_a_response_not_bound_to_the_original_bytes(self) -> None:
        api = Mock()
        api.search.return_value = {"query": {"rawDigest": "0x" + "ff" * 32}}
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "query.cnf")
            path.write_bytes(b"p cnf 0 0\n")
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                self.assertRaisesRegex(RuntimeError, "raw digest does not match"),
            ):
                command_search(argparse.Namespace(cnf=str(path), json=True))

    def test_standardize_writes_canonical_lf_bytes_without_platform_conversion(self) -> None:
        api = Mock()
        api.standardize.return_value = {
            "variables": 1,
            "clauses": 1,
            "canonicalDigest": "0x" + "11" * 32,
            "canonicalText": "p cnf 1 1\n1 0\n",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory, "source.cnf")
            output = Path(temporary_directory, "nested", "canonical.cnf")
            source.write_bytes(b"p cnf 1 1\r\n1 0\r\n")
            args = argparse.Namespace(
                cnf=str(source), json=False, output=str(output), print_text=False
            )
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                redirect_stdout(io.StringIO()),
            ):
                command_standardize(args)
            self.assertEqual(output.read_bytes(), b"p cnf 1 1\n1 0\n")

    def test_standardize_and_search_reject_locally_before_loading_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "invalid.cnf")
            path.write_bytes(b"cat is not a comment\np cnf 0 0\n")
            with patch("threesat_cli.main.load_config") as load_config:
                with self.assertRaises(InvalidDimacsError):
                    command_standardize(
                        argparse.Namespace(
                            cnf=str(path), json=True, output=None, print_text=False
                        )
                    )
                with self.assertRaises(InvalidDimacsError):
                    command_search(argparse.Namespace(cnf=str(path), json=True))
            load_config.assert_not_called()

    def test_issue_parses_hashes_and_uploads_one_identical_raw_payload(self) -> None:
        payload = b"\xef\xbb\xbfp cnf 1 1\r\n1 0\r\n"
        digest = Web3.keccak(payload).hex()
        digest = digest if digest.startswith("0x") else f"0x{digest}"
        api = Mock()
        api.prepare_create_bounty.side_effect = [
            {"verifierRewardPool": "0", "verifierRewardBps": 0},
            {"prepared": True},
        ]
        api.upload_file.side_effect = [
            {"ref": "r2://instance", "digest": digest},
            {"ref": "r2://metadata", "digest": "0x" + "33" * 32},
        ]
        api.build_metadata.return_value = {"payload": "{}", "fileName": "metadata.json"}

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "problem.cnf")
            path.write_bytes(payload)
            args = build_parser().parse_args(
                ["issue", str(path), "--reward", "1", "--json"]
            )
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                redirect_stdout(io.StringIO()),
            ):
                command_issue(args)

        first_prepare = api.prepare_create_bounty.call_args_list[0].args[0]
        self.assertEqual(first_prepare["instanceDigest"].lower(), digest.lower())
        instance_upload = api.upload_file.call_args_list[0]
        self.assertEqual(instance_upload.args[0], "instance")
        self.assertEqual(instance_upload.kwargs["content"], payload)

    def test_api_instance_upload_cannot_bypass_parser_with_path_or_content(self) -> None:
        api = ProtocolApi("https://example.test")
        api.session.post = Mock()
        invalid = b"p cnf 1 1\n+1 0\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "problem.cnf")
            path.write_bytes(invalid)
            with self.assertRaises(InvalidDimacsError):
                api.upload_file("instance", path)
            with self.assertRaises(InvalidDimacsError):
                api.upload_file("instance", path, content=invalid)
        api.session.post.assert_not_called()

    def test_api_instance_upload_freezes_mutable_content_before_posting(self) -> None:
        response = Mock(
            ok=True,
            status_code=200,
            reason="OK",
            text='{"digest":"0x01"}',
            headers={"content-type": "application/json"},
        )
        response.json.return_value = {"digest": "0x01"}
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = response
        source = bytearray(b"p cnf 1 1\n1 0\n")

        api.upload_file("instance", Path("problem.cnf"), content=source)
        source[:] = b"x" * len(source)

        posted = api.session.post.call_args.kwargs["files"]["file"][1]
        self.assertIsInstance(posted, bytes)
        self.assertEqual(posted, b"p cnf 1 1\n1 0\n")

    def test_api_instance_rejects_oversized_memoryview_before_network_use(self) -> None:
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        oversized = memoryview(bytearray(4 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(RuntimeError, "4 MiB"):
            api.upload_file("instance", Path("problem.cnf"), content=oversized)
        api.session.post.assert_not_called()

    def test_matched_cnf_api_methods_cannot_bypass_the_strict_parser(self) -> None:
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        invalid = ("invalid.cnf", b"p cnf 1 1\n+1 0\n")
        with self.assertRaises(InvalidDimacsError):
            api.download_answer(
                bounty_id="1",
                wallet="0x1111111111111111111111111111111111111111",
                timestamp="1700000000000",
                signature="0xsig",
                query_file=invalid,
            )
        with self.assertRaises(InvalidDimacsError):
            api.upload_unsat_transform_target(
                bounty_id="1",
                wallet="0x1111111111111111111111111111111111111111",
                timestamp="1700000000000",
                signature="0xsig",
                query_file=invalid,
            )
        api.session.post.assert_not_called()
        api.session.put.assert_not_called()

    def test_issue_rejects_storage_digest_mismatch_before_metadata(self) -> None:
        api = Mock()
        api.prepare_create_bounty.return_value = {
            "verifierRewardPool": "0",
            "verifierRewardBps": 0,
        }
        api.upload_file.return_value = {
            "ref": "r2://instance",
            "digest": "0x" + "ff" * 32,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "problem.cnf")
            path.write_bytes(b"p cnf 1 1\n1 0\n")
            args = build_parser().parse_args(
                ["issue", str(path), "--reward", "1", "--json"]
            )
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, "digest does not match"),
            ):
                command_issue(args)
        api.build_metadata.assert_not_called()

    def test_matched_query_is_strictly_validated_and_preserves_bytes(self) -> None:
        valid = b"\xef\xbb\xbfp cnf 1 1\r1 0\r"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "query.cnf")
            path.write_bytes(valid)
            self.assertEqual(_read_matched_query(str(path)), ("query.cnf", valid))
            path.write_bytes(b"p cnf 1 1\n+1 0\n")
            with self.assertRaises(InvalidDimacsError):
                _read_matched_query(str(path))

    def test_sat_upload_requires_strict_nonconflicting_unit_cnf_before_key_or_api(self) -> None:
        invalid_payloads = (
            b"p cnf 1 1\n+1 0\n",
            b"p cnf 2 1\n1 2 0\n",
            b"p cnf 1 2\n1 0\n-1 0\n",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "assignment.cnf")
            for payload in invalid_payloads:
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    args = argparse.Namespace(
                        solution=str(path),
                        kind="sat",
                        proof_format="drat",
                        private_key="0x" + "11" * 32,
                        json=True,
                    )
                    with (
                        patch("threesat_cli.main.load_config") as load_config,
                        patch("threesat_cli.main.require_private_key") as private_key,
                        self.assertRaises(ValueError),
                    ):
                        command_upload_solution(args)
                    load_config.assert_not_called()
                    private_key.assert_not_called()

    def test_valid_sat_unit_cnf_reaches_authenticated_upload(self) -> None:
        payload = b"p cnf 2 3\n1 0\n1 0\n-2 0\n"
        digest = Web3.keccak(payload).hex()
        digest = digest if digest.startswith("0x") else f"0x{digest}"
        api = Mock()
        api.initialize_solution_upload.return_value = {"id": "upload-id"}
        api.upload_reserved_solution.return_value = ("upload-id", "token")
        api.complete_solution_upload.return_value = {
            "artifactId": "artifact-" + "ab" * 24,
            "digest": digest,
            "name": "assignment.cnf",
            "size": len(payload),
            "solutionKind": 1,
            "proofFormat": 0,
        }
        signed = {
            "wallet": "0x1111111111111111111111111111111111111111",
            "timestamp": "1700000000000",
            "signature": "0xsig",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "assignment.cnf")
            path.write_bytes(payload)
            args = argparse.Namespace(
                solution=str(path),
                kind="sat",
                proof_format="drat",
                private_key="0x" + "11" * 32,
                json=True,
            )
            with (
                patch("threesat_cli.main.load_config", return_value=protocol_config()),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main.sign_solution_upload_message", return_value=signed),
                redirect_stdout(io.StringIO()),
            ):
                command_upload_solution(args)

        initialized = api.initialize_solution_upload.call_args.kwargs
        self.assertEqual(initialized["digest"].lower(), digest.lower())
        self.assertEqual(initialized["size"], len(payload))
        self.assertEqual(initialized["solution_kind"], 1)
        self.assertEqual(initialized["proof_format"], 0)
        self.assertEqual(api.upload_reserved_solution.call_args.kwargs["content"], payload)


if __name__ == "__main__":
    unittest.main()
