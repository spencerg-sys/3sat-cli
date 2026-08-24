from __future__ import annotations

import json
import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
import requests

from eth_account import Account
from eth_account.messages import encode_defunct

from threesat_cli.api import ProtocolApi
from threesat_cli.chain import sign_solution_upload_message, solution_upload_auth_message
from threesat_cli.main import command_upload_solution


def json_response(payload: dict, *, status: int = 200) -> Mock:
    body = json.dumps(payload)
    response = Mock(
        ok=200 <= status < 300,
        status_code=status,
        reason="OK",
        text=body,
        headers={"content-type": "application/json"},
    )
    response.json.return_value = payload
    return response


class DirectSolutionUploadTests(unittest.TestCase):
    def test_legacy_multipart_api_rejects_solution_artifacts(self) -> None:
        api = ProtocolApi("https://example.test")
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "answer.cnf")
            path.write_bytes(b"p cnf 1 1\n1 0\n")
            with self.assertRaisesRegex(RuntimeError, "authenticated upload flow"):
                api.upload_file("solution", path)

    def test_upload_solution_command_uses_authenticated_direct_flow_for_small_files(self) -> None:
        digest = "0x" + "22" * 32
        api = Mock()
        api.initialize_solution_upload.return_value = {
            "id": "11111111-1111-4111-8111-111111111111"
        }
        api.upload_reserved_solution.return_value = (
            "11111111-1111-4111-8111-111111111111",
            "secret-token",
        )
        api.complete_solution_upload.return_value = {
            "artifactId": "artifact-" + "ab" * 24,
            "digest": digest,
            "name": "proof.frat",
            "size": 5,
            "solutionKind": 2,
            "proofFormat": 2,
        }
        signed = {
            "wallet": "0x1111111111111111111111111111111111111111",
            "timestamp": "1700000000000",
            "signature": "0xsig",
            "message": "message",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "proof.frat")
            path.write_bytes(b"proof")
            args = argparse.Namespace(
                solution=str(path),
                kind="unsat",
                proof_format="frat",
                private_key="0x" + "11" * 32,
                json=True,
            )
            output = io.StringIO()
            with (
                patch("threesat_cli.main.load_config", return_value={
                    "chain_id": 421614,
                    "bounty_manager": "0x942b326b190d588fe1bb3931502f509c9f9ec767",
                }),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main._keccak_file_hex", return_value=digest),
                patch("threesat_cli.main.sign_solution_upload_message", return_value=signed) as signer,
                redirect_stdout(output),
            ):
                command_upload_solution(args)

        api.upload_file.assert_not_called()
        api.initialize_solution_upload.assert_called_once()
        api.upload_reserved_solution.assert_called_once()
        api.complete_solution_upload.assert_called_once()
        self.assertEqual([call.kwargs["action"] for call in signer.call_args_list], ["reserve", "complete"])
        printed = json.loads(output.getvalue())
        self.assertEqual(printed["artifactId"], "artifact-" + "ab" * 24)
        self.assertNotIn("storedName", printed)

    def test_auth_message_matches_the_website_contract_and_binds_unicode_name(self) -> None:
        message = solution_upload_auth_message(
            action="complete",
            wallet="0x1111111111111111111111111111111111111111",
            upload_id="11111111-1111-4111-8111-111111111111",
            token_hash="0x" + "44" * 32,
            file_name="证明.frat",
            size=123,
            digest="0x" + "22" * 32,
            solution_kind=2,
            proof_format=2,
            timestamp="1700000000000",
            chain_id=421614,
            bounty_manager="0x942b326b190d588fe1bb3931502f509c9f9ec767",
        )
        self.assertEqual(
            message,
            "\n".join(
                [
                    "3SAT Solution Artifact Upload",
                    "action: complete",
                    "chainId: 421614",
                    "bountyManager: 0x942b326b190d588fe1bb3931502f509c9f9ec767",
                    "wallet: 0x1111111111111111111111111111111111111111",
                    "uploadId: 11111111-1111-4111-8111-111111111111",
                    "tokenHash: 0x" + "44" * 32,
                    "solutionKind: 2",
                    "proofFormat: 2",
                    "digest: 0x" + "22" * 32,
                    "size: 123",
                    "fileNameUtf8: 0xe8af81e6988e2e66726174",
                    "timestamp: 1700000000000",
                ]
            ),
        )

    def test_signer_recovers_the_wallet(self) -> None:
        private_key = "0x" + "11" * 32
        signed = sign_solution_upload_message(
            private_key,
            action="reserve",
            chain_id=421614,
            bounty_manager="0x942b326b190d588fe1bb3931502f509c9f9ec767",
            file_name="proof.frat",
            size=123,
            digest="0x" + "22" * 32,
            solution_kind=2,
            proof_format=2,
            upload_id="11111111-1111-4111-8111-111111111111",
            token_hash="0x" + "44" * 32,
        )
        self.assertTrue(signed["signature"].startswith("0x"))
        self.assertEqual(len(signed["signature"]), 132)
        recovered = Account.recover_message(
            encode_defunct(text=signed["message"]), signature=signed["signature"]
        )
        self.assertEqual(recovered.lower(), signed["wallet"].lower())

    def test_api_uses_fixed_reservation_url_and_streams_file_to_r2_before_completion(self) -> None:
        digest = "0x" + "22" * 32
        reservation = {
            "id": "11111111-1111-4111-8111-111111111111",
            "token": "secret-upload-token",
            "digest": digest,
            "size": 5,
            "fileName": "proof.frat",
            "solutionKind": 2,
            "proofFormat": 2,
            "upload": {
                "url": "https://objects.example.test/staging?signature=fixed",
                "method": "PUT",
                "headers": {"Content-Type": "application/octet-stream"},
            },
        }
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.side_effect = [
            json_response({"upload": reservation}, status=201),
            json_response({"artifactId": "artifact-" + "ab" * 24, "digest": digest}),
        ]
        api.session.put.return_value = Mock(ok=True, status_code=200, reason="OK")

        initialized = api.initialize_solution_upload(
            upload_id="11111111-1111-4111-8111-111111111111",
            token="secret-upload-token",
            wallet="0x1111111111111111111111111111111111111111",
            timestamp="1700000000000",
            signature="0xsig",
            file_name="proof.frat",
            size=5,
            digest=digest,
            solution_kind=2,
            proof_format=2,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "proof.frat")
            path.write_bytes(b"proof")
            upload_id, token = api.upload_reserved_solution(path, initialized)
        result = api.complete_solution_upload(
            upload_id=upload_id,
            token=token,
            wallet="0x1111111111111111111111111111111111111111",
            timestamp="1700000000001",
            signature="0xcomplete",
        )

        self.assertEqual(result["artifactId"], "artifact-" + "ab" * 24)
        put_call = api.session.put.call_args
        self.assertEqual(put_call.args[0], reservation["upload"]["url"])
        self.assertEqual(put_call.kwargs["headers"], reservation["upload"]["headers"])
        self.assertTrue(put_call.kwargs["data"].closed)
        self.assertEqual(
            api.session.post.call_args_list[1].args[0],
            "https://example.test/api/protocol/storage/uploads/11111111-1111-4111-8111-111111111111/complete",
        )
        self.assertEqual(api.session.post.call_args_list[1].kwargs["json"]["token"], "secret-upload-token")

    def test_http_adapter_never_implicitly_replays_post(self) -> None:
        api = ProtocolApi("https://example.test")
        retries = api.session.adapters["https://"].max_retries
        self.assertNotIn("POST", retries.allowed_methods)

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_idempotent_reservation_retries_response_loss_with_identical_identity(self, _sleep: Mock) -> None:
        digest = "0x" + "22" * 32
        upload_id = "11111111-1111-4111-8111-111111111111"
        token = "secret-upload-token-that-is-long-enough-123456"
        reservation = {
            "id": upload_id,
            "token": token,
            "digest": digest,
            "size": 5,
            "fileName": "proof.frat",
            "solutionKind": 2,
            "proofFormat": 2,
            "upload": {"url": "https://objects.example.test/fixed", "method": "PUT", "headers": {}},
        }
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.side_effect = [
            requests.ConnectionError("response lost"),
            json_response({"upload": reservation}, status=201),
        ]
        result = api.initialize_solution_upload(
            upload_id=upload_id,
            token=token,
            wallet="0x1111111111111111111111111111111111111111",
            timestamp="1700000000000",
            signature="0xsig",
            file_name="proof.frat",
            size=5,
            digest=digest,
            solution_kind=2,
            proof_format=2,
        )
        self.assertEqual(result["id"], upload_id)
        first = api.session.post.call_args_list[0].kwargs["json"]
        second = api.session.post.call_args_list[1].kwargs["json"]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
