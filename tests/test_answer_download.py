from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from web3 import Web3

from threesat_cli.api import ProtocolApi
from threesat_cli.main import (
    _finalized_winner_solution_kind,
    _read_matched_query,
    build_parser,
    command_download_answer,
)


def json_response(payload: dict, *, status: int = 200) -> Mock:
    body = json.dumps(payload)
    response = Mock(
        ok=200 <= status < 300,
        status_code=status,
        text=body,
        content=body.encode(),
        headers={"content-type": "application/json"},
    )
    response.json.return_value = payload
    return response


class MatchedAnswerTests(unittest.TestCase):
    def test_download_transform_timeout_defaults_to_sixty_minutes_and_is_configurable(self) -> None:
        parser = build_parser()
        self.assertEqual(
            parser.parse_args(["download-answer", "7"]).transform_timeout_minutes,
            60,
        )
        self.assertEqual(
            parser.parse_args(
                ["download-answer", "7", "--transform-timeout-minutes", "90"]
            ).transform_timeout_minutes,
            90,
        )

    def test_query_reader_preserves_original_bytes(self) -> None:
        payload = b"\xef\xbb\xbfp cnf 1 1\r\n1 0\r\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "query.cnf")
            path.write_bytes(payload)

            self.assertEqual(_read_matched_query(str(path)), ("query.cnf", payload))

    def test_api_posts_original_bytes_as_multipart_file(self) -> None:
        payload = b"\xef\xbb\xbfp cnf 1 1\r\n1 0\r\n"
        response = Mock(
            ok=True,
            status_code=200,
            content=b"zip",
            headers={"content-disposition": 'attachment; filename="answer.zip"'},
        )
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = response

        result = api.download_answer(
            bounty_id="7",
            wallet="0xwallet",
            timestamp="123",
            signature="0xsig",
            query_file=("query.cnf", payload),
        )

        self.assertEqual(result, (b"zip", 'attachment; filename="answer.zip"'))
        api.session.post.assert_called_once_with(
            "https://example.test/api/protocol/bundles/answer",
            data={
                "bountyId": "7",
                "wallet": "0xwallet",
                "timestamp": "123",
                "signature": "0xsig",
            },
            files={"file": ("query.cnf", payload, "text/plain")},
            timeout=120,
        )

    def test_api_uploads_large_unsat_target_directly_and_uses_upload_handle(self) -> None:
        payload = b"p cnf 1 2\n1 0\n-1 0\n"
        expected_digest = Web3.keccak(payload).hex()
        if not expected_digest.startswith("0x"):
            expected_digest = f"0x{expected_digest}"
        fixed_upload_id = "11111111-1111-4111-8111-111111111111"
        fixed_upload_token = "fixed-target-upload-token-that-is-long-enough"
        initialized = json_response(
            {
                "upload": {
                    "id": fixed_upload_id,
                    "token": fixed_upload_token,
                    "digest": expected_digest,
                    "size": len(payload),
                    "upload": {
                        "url": "https://objects.example.test/target.cnf?signature=test",
                        "method": "PUT",
                        "headers": {"Content-Type": "text/plain"},
                    },
                }
            },
            status=201,
        )
        direct_put = Mock(ok=True, status_code=200, reason="OK")
        answer = Mock(
            ok=True,
            status_code=200,
            content=b"zip",
            headers={"content-disposition": 'attachment; filename="answer.zip"'},
        )
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.side_effect = [initialized, answer]
        api.session.put.return_value = direct_put

        with (
            patch("threesat_cli.api.uuid.uuid4", return_value=fixed_upload_id),
            patch("threesat_cli.api.secrets.token_urlsafe", return_value=fixed_upload_token),
        ):
            handle = api.upload_unsat_transform_target(
                bounty_id="7",
                wallet="0xwallet",
                timestamp="123",
                signature="0xsig",
                query_file=("query.cnf", payload),
            )
        result = api.download_answer(
            bounty_id="7",
            wallet="0xwallet",
            timestamp="124",
            signature="0xnewsig",
            query_file=None,
            query_upload=handle,
        )

        self.assertEqual(handle, (fixed_upload_id, fixed_upload_token))
        self.assertEqual(result, (b"zip", 'attachment; filename="answer.zip"'))
        init_payload = api.session.post.call_args_list[0].kwargs["json"]
        self.assertEqual(init_payload["size"], len(payload))
        self.assertEqual(init_payload["digest"].lower(), expected_digest.lower())
        self.assertEqual(init_payload["uploadId"], fixed_upload_id)
        self.assertEqual(init_payload["uploadToken"], fixed_upload_token)
        api.session.put.assert_called_once_with(
            "https://objects.example.test/target.cnf?signature=test",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=300,
        )
        self.assertEqual(
            api.session.post.call_args_list[1].kwargs["json"],
            {
                "bountyId": "7",
                "wallet": "0xwallet",
                "timestamp": "124",
                "signature": "0xnewsig",
                "uploadId": fixed_upload_id,
                "uploadToken": fixed_upload_token,
            },
        )

    def test_finds_only_the_finalized_winner_solution_kind(self) -> None:
        result = {
            "bounty": {"finalizedWinningSubmissionId": "2"},
            "submissions": [
                {"submissionId": "1", "solutionKind": 1},
                {"submissionId": "2", "solutionKind": 2},
            ],
        }
        self.assertEqual(_finalized_winner_solution_kind(result), 2)
        result["bounty"]["finalizedWinningSubmissionId"] = "0"
        self.assertIsNone(_finalized_winner_solution_kind(result))

    def test_large_sat_matched_target_uses_direct_upload(self) -> None:
        api = Mock()
        api.bounty.return_value = {
            "bountyId": "7",
            "bountyCode": "SAT-TEST",
            "bounty": {
                "instanceDigest": "0x" + "99" * 32,
                "finalizedWinningSubmissionId": "2",
            },
            "submissions": [{"submissionId": "2", "solutionKind": 1}],
        }
        api.upload_unsat_transform_target.return_value = ("upload-id", "upload-token")
        api.download_answer.return_value = (b"zip", None)
        auth = {
            "wallet": "0x1111111111111111111111111111111111111111",
            "timestamp": "1700000000000",
            "signature": "0xsig",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory, "answer.zip")
            args = argparse.Namespace(
                bounty="7",
                cnf=None,
                private_key="0x" + "11" * 32,
                transform_timeout_minutes=60,
                output=str(output),
            )
            with (
                patch("threesat_cli.main.DIRECT_MATCHED_CNF_UPLOAD_THRESHOLD_BYTES", 0),
                patch(
                    "threesat_cli.main.load_config",
                    return_value={
                        "chain_id": 421614,
                        "bounty_manager": "0x4158b40e1aa41cd386b7936b1023fe094f77fed1",
                    },
                ),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main.require_private_key", return_value="0x" + "11" * 32),
                patch("threesat_cli.main.sign_access_message", return_value=auth),
            ):
                command_download_answer(
                    args,
                    query_file=("matched.cnf", b"p cnf 1 1\n1 0\n"),
                )
            self.assertEqual(output.read_bytes(), b"zip")
        api.upload_unsat_transform_target.assert_called_once()
        self.assertIsNone(api.download_answer.call_args.kwargs["query_file"])
        self.assertEqual(
            api.download_answer.call_args.kwargs["query_upload"],
            ("upload-id", "upload-token"),
        )

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_api_polls_transform_job_and_verifies_download(self, _sleep: Mock) -> None:
        zip_payload = b"verified zip bytes"
        zip_digest = Web3.keccak(zip_payload).hex()
        if not zip_digest.startswith("0x"):
            zip_digest = f"0x{zip_digest}"
        queued = json_response(
            {
                "code": "UNSAT_PROOF_TRANSFORM_QUEUED",
                "job": {
                    "id": "job-12345678",
                    "status": "queued",
                    "accessToken": "access-token",
                    "pollUrl": "/api/protocol/unsat-transform/jobs/job-12345678",
                },
                "pollAfterMs": 250,
            },
            status=202,
        )
        processing = json_response(
            {
                "job": {"id": "job-12345678", "status": "processing"},
                "pollAfterMs": 250,
            }
        )
        succeeded = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "succeeded",
                    "output": {"zipDigest": zip_digest, "size": len(zip_payload)},
                },
                "download": {"url": "https://objects.example.test/result.zip"},
            }
        )
        download = Mock(
            ok=True,
            status_code=200,
            content=zip_payload,
            headers={"content-disposition": 'attachment; filename="transformed.zip"'},
        )
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = queued
        api.session.get.side_effect = [processing, succeeded, download]

        result = api.download_answer(
            bounty_id="7",
            wallet="0xwallet",
            timestamp="123",
            signature="0xsig",
            query_file=("query.cnf", b"p cnf 1 2\n1 0\n-1 0\n"),
        )

        self.assertEqual(result, (zip_payload, 'attachment; filename="transformed.zip"'))
        poll_headers = {"Authorization": "Bearer access-token"}
        self.assertEqual(api.session.get.call_args_list[0].kwargs, {"headers": poll_headers, "timeout": 60})
        self.assertEqual(api.session.get.call_args_list[1].kwargs, {"headers": poll_headers, "timeout": 60})
        self.assertEqual(api.session.get.call_args_list[2].kwargs, {"headers": None, "timeout": 300})

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_api_surfaces_fail_closed_transform_error(self, _sleep: Mock) -> None:
        queued = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "queued",
                    "accessToken": "access-token",
                    "pollUrl": "/api/protocol/unsat-transform/jobs/job-12345678",
                }
            },
            status=202,
        )
        failed = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "failed",
                    "error": {
                        "code": "TARGET_PROOF_REJECTED",
                        "message": "The target checker rejected the transformed proof.",
                    },
                }
            }
        )
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = queued
        api.session.get.return_value = failed

        with self.assertRaisesRegex(RuntimeError, "TARGET_PROOF_REJECTED"):
            api.download_answer(
                bounty_id="7",
                wallet="0xwallet",
                timestamp="123",
                signature="0xsig",
                query_file=("query.cnf", b"p cnf 1 2\n1 0\n-1 0\n"),
            )

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_api_rejects_corrupted_transform_download(self, _sleep: Mock) -> None:
        queued = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "queued",
                    "accessToken": "access-token",
                    "pollUrl": "/api/protocol/unsat-transform/jobs/job-12345678",
                }
            },
            status=202,
        )
        succeeded = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "succeeded",
                    "output": {"zipDigest": "0x" + "11" * 32, "size": 3},
                },
                "download": {"url": "https://objects.example.test/result.zip"},
            }
        )
        download = Mock(ok=True, status_code=200, content=b"zip", headers={})
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = queued
        api.session.get.side_effect = [succeeded, download]

        with self.assertRaisesRegex(RuntimeError, "digest does not match"):
            api.download_answer(
                bounty_id="7",
                wallet="0xwallet",
                timestamp="123",
                signature="0xsig",
                query_file=("query.cnf", b"p cnf 1 2\n1 0\n-1 0\n"),
            )

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_api_rejects_missing_or_malformed_transform_output_binding(self, _sleep: Mock) -> None:
        queued = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "queued",
                    "accessToken": "access-token",
                    "pollUrl": "/api/protocol/unsat-transform/jobs/job-12345678",
                }
            },
            status=202,
        )
        cases = [
            (None, "missing its verified output"),
            ({"size": 3}, "invalid output digest"),
            ({"zipDigest": "0x" + "11" * 32, "size": 0}, "invalid output size"),
            ({"zipDigest": "not-a-digest", "size": 3}, "invalid output digest"),
        ]
        for output, expected_error in cases:
            with self.subTest(output=output):
                job = {"id": "job-12345678", "status": "succeeded"}
                if output is not None:
                    job["output"] = output
                succeeded = json_response(
                    {"job": job, "download": {"url": "https://objects.example.test/result.zip"}}
                )
                api = ProtocolApi("https://example.test")
                api.session = Mock()
                api.session.post.return_value = queued
                api.session.get.return_value = succeeded
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    api.download_answer(
                        bounty_id="7",
                        wallet="0xwallet",
                        timestamp="123",
                        signature="0xsig",
                        query_file=("query.cnf", b"p cnf 1 2\n1 0\n-1 0\n"),
                    )

    @patch("threesat_cli.api.time.sleep", return_value=None)
    def test_api_rejects_transform_download_size_mismatch(self, _sleep: Mock) -> None:
        queued = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "queued",
                    "accessToken": "access-token",
                    "pollUrl": "/api/protocol/unsat-transform/jobs/job-12345678",
                }
            },
            status=202,
        )
        succeeded = json_response(
            {
                "job": {
                    "id": "job-12345678",
                    "status": "succeeded",
                    "output": {"zipDigest": "0x" + "11" * 32, "size": 4},
                },
                "download": {"url": "https://objects.example.test/result.zip"},
            }
        )
        download = Mock(ok=True, status_code=200, content=b"zip", headers={})
        api = ProtocolApi("https://example.test")
        api.session = Mock()
        api.session.post.return_value = queued
        api.session.get.side_effect = [succeeded, download]
        with self.assertRaisesRegex(RuntimeError, "size does not match"):
            api.download_answer(
                bounty_id="7",
                wallet="0xwallet",
                timestamp="123",
                signature="0xsig",
                query_file=("query.cnf", b"p cnf 1 2\n1 0\n-1 0\n"),
            )


if __name__ == "__main__":
    unittest.main()
