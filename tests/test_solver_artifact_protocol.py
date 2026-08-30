from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from threesat_cli.chain import BOUNTY_MANAGER_ABI, compute_solution_commit_hash
from threesat_cli.main import (
    _commit_solution_data,
    _default_reveal_bundle_path,
    _prepare_commit_payload,
    _validated_solution_artifact,
    build_parser,
    command_commit,
    command_prepare_commit,
    command_reveal,
)


ARTIFACT_ID = "artifact-" + "ab" * 24
DIGEST = "0x" + "22" * 32
SALT = "0x" + "33" * 32
SOLVER = "0x1111111111111111111111111111111111111111"


def abi_item(name: str, item_type: str = "function") -> dict:
    return next(
        item
        for item in BOUNTY_MANAGER_ABI
        if item.get("type") == item_type and item.get("name") == name
    )


class SolverArtifactProtocolTests(unittest.TestCase):
    @staticmethod
    def _prepared_commit(manager: str) -> dict:
        commit_hash = compute_solution_commit_hash(
            chain_id=421614,
            bounty_manager=manager,
            bounty_id=7,
            solver=SOLVER,
            solution_kind=1,
            proof_format=0,
            solution_digest=DIGEST,
            salt=SALT,
        )
        reveal_bundle = {
            "bountyId": "7",
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "proofFormat": 0,
            "solutionDigest": DIGEST,
            "salt": SALT,
            "commitHash": commit_hash,
        }
        return {
            "chainId": 421614,
            "artifactId": ARTIFACT_ID,
            "bountyManager": manager,
            "bountyId": "7",
            "bountyCode": "SAT-TEST",
            "solver": SOLVER,
            "bondToken": "0x3333333333333333333333333333333333333333",
            "solverBond": "10",
            "solutionKind": 1,
            "solutionKindCode": "SAT",
            "proofFormat": 0,
            "proofFormatName": "None",
            "solutionDigest": DIGEST,
            "salt": SALT,
            "commitHash": commit_hash,
            "revealBundle": reveal_bundle,
            "transactions": [
                {
                    "label": "Commit solution",
                    "functionName": "commitSolution",
                    "to": manager,
                    "data": _commit_solution_data("7", commit_hash),
                    "value": "0",
                    "args": ["7", commit_hash],
                }
            ],
        }

    def test_parser_and_commit_payload_use_the_opaque_artifact_id(self) -> None:
        parsed = build_parser().parse_args(
            [
                "prepare-commit",
                "7",
                "--solver",
                SOLVER,
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                DIGEST,
            ]
        )
        payload = _prepare_commit_payload(parsed, {})

        self.assertEqual(
            payload,
            {
                "bounty": "7",
                "solver": SOLVER,
                "solutionKind": 1,
                "proofFormat": 0,
                "artifactId": ARTIFACT_ID,
                "solutionDigest": DIGEST,
            },
        )

    def test_solution_upload_output_is_limited_to_the_opaque_public_binding(self) -> None:
        public = _validated_solution_artifact(
            {
                "artifactId": ARTIFACT_ID,
                "digest": DIGEST,
                "name": "answer.cnf",
                "size": 12,
                "solutionKind": 1,
                "proofFormat": 0,
                "objectKey": "private/objects/answer.cnf",
                "storedName": "internal-name.cnf",
                "storage": "private",
            },
            digest=DIGEST,
            name="answer.cnf",
            size=12,
            solution_kind=1,
            proof_format=0,
        )

        self.assertEqual(public["artifactId"], ARTIFACT_ID)
        self.assertEqual(
            set(public),
            {
                "artifactId",
                "digest",
                "name",
                "size",
                "solutionKind",
                "solutionKindName",
                "proofFormat",
                "proofFormatName",
            },
        )

    def test_prepare_commit_keeps_artifact_id_only_in_the_offchain_bundle(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        prepared = self._prepared_commit(manager)
        commit_hash = prepared["commitHash"]
        api = Mock()
        api.prepare_commit.return_value = prepared
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory, "reveal.json")
            args = argparse.Namespace(
                bounty="7",
                solver=SOLVER,
                artifact_id=ARTIFACT_ID,
                solution_digest=DIGEST,
                kind="sat",
                proof_format="drat",
                salt=None,
                private_key=None,
                output=str(output),
                json=True,
            )
            with (
                patch(
                    "threesat_cli.main.load_config",
                    return_value={"chain_id": 421614, "bounty_manager": manager},
                ),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main._synchronize_commit_bond"),
                redirect_stdout(io.StringIO()),
            ):
                command_prepare_commit(args)

            bundle = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(bundle["artifactId"], ARTIFACT_ID)
        self.assertEqual(prepared["transactions"][0]["args"], ["7", commit_hash])
        self.assertEqual(api.prepare_commit.call_args.args[0]["artifactId"], ARTIFACT_ID)

    def test_commit_send_persists_a_default_reveal_bundle_before_broadcast(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        prepared = self._prepared_commit(manager)
        api = Mock()
        api.prepare_commit.return_value = prepared
        chain = Mock()
        chain.send_prepared_transaction.return_value = {"hash": "0x1", "status": 1, "gasUsed": 1}
        args = build_parser().parse_args(
            [
                "commit",
                "7",
                "--solver",
                SOLVER,
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                DIGEST,
                "--private-key",
                "0x" + "44" * 32,
                "--send",
            ]
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            bundle_directory = Path(temporary_directory, "data", "reveal-bundles")
            expected_path = bundle_directory / _default_reveal_bundle_path(prepared).name

            def assert_bundle_exists_before_send(_transaction: dict, _key: str) -> dict:
                self.assertTrue(expected_path.is_file())
                self.assertEqual(
                    json.loads(expected_path.read_text(encoding="utf-8")),
                    prepared["revealBundle"],
                )
                return {"hash": "0x1", "status": 1, "gasUsed": 1}

            chain.send_prepared_transaction.side_effect = assert_bundle_exists_before_send
            with (
                patch(
                    "threesat_cli.main.load_config",
                    return_value={"chain_id": 421614, "bounty_manager": manager},
                ),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main._synchronize_commit_bond", return_value=chain),
                patch("threesat_cli.main.DEFAULT_REVEAL_BUNDLE_DIRECTORY", bundle_directory),
                patch("threesat_cli.main._print_commit_preview"),
                redirect_stdout(io.StringIO()),
            ):
                command_commit(args)

            self.assertEqual(chain.send_prepared_transaction.call_count, 1)
            self.assertFalse(list(bundle_directory.glob("*.tmp")))
            if os.name != "nt":
                self.assertEqual(expected_path.stat().st_mode & 0o777, 0o600)

    def test_commit_send_honors_explicit_output_and_saves_before_broadcast(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        prepared = self._prepared_commit(manager)
        api = Mock()
        api.prepare_commit.return_value = prepared
        chain = Mock()
        args = build_parser().parse_args(
            [
                "commit",
                "7",
                "--solver",
                SOLVER,
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                DIGEST,
                "--private-key",
                "0x" + "44" * 32,
                "--send",
            ]
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory, "custom", "reveal.json")
            args.output = str(output)

            def assert_explicit_bundle_exists(_transaction: dict, _key: str) -> dict:
                self.assertEqual(json.loads(output.read_text(encoding="utf-8")), prepared["revealBundle"])
                return {"hash": "0x1", "status": 1, "gasUsed": 1}

            chain.send_prepared_transaction.side_effect = assert_explicit_bundle_exists
            with (
                patch(
                    "threesat_cli.main.load_config",
                    return_value={"chain_id": 421614, "bounty_manager": manager},
                ),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main._synchronize_commit_bond", return_value=chain),
                patch("threesat_cli.main._print_commit_preview"),
                redirect_stdout(io.StringIO()),
            ):
                command_commit(args)

            self.assertEqual(chain.send_prepared_transaction.call_count, 1)

    def test_commit_does_not_broadcast_when_reveal_bundle_write_fails(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        prepared = self._prepared_commit(manager)
        api = Mock()
        api.prepare_commit.return_value = prepared
        chain = Mock()
        args = build_parser().parse_args(
            [
                "commit",
                "7",
                "--solver",
                SOLVER,
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                DIGEST,
                "--private-key",
                "0x" + "44" * 32,
                "--send",
            ]
        )

        with (
            patch(
                "threesat_cli.main.load_config",
                return_value={"chain_id": 421614, "bounty_manager": manager},
            ),
            patch("threesat_cli.main.make_api", return_value=api),
            patch("threesat_cli.main._synchronize_commit_bond", return_value=chain),
            patch("threesat_cli.main._write_reveal_bundle", side_effect=OSError("disk full")),
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(OSError, "disk full"),
        ):
            command_commit(args)

        chain.send_prepared_transaction.assert_not_called()

    def test_default_bundle_filename_cannot_escape_its_directory(self) -> None:
        path = _default_reveal_bundle_path(
            {
                "bountyId": "../../7:unsafe",
                "commitHash": "../0xabc/../../secret",
            }
        )
        self.assertEqual(path.parent, Path("data", "reveal-bundles"))
        self.assertNotIn("..", path.name)
        self.assertNotIn("/", path.name)
        self.assertNotIn("\\", path.name)

    def test_commit_rejects_a_reveal_bundle_not_bound_to_the_verified_descriptor(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        fields = {
            "bountyId": "8",
            "artifactId": "artifact-" + "cd" * 24,
            "solutionKind": 2,
            "proofFormat": 1,
            "solutionDigest": "0x" + "77" * 32,
            "salt": "0x" + "88" * 32,
            "commitHash": "0x" + "99" * 32,
            "submissionId": "123",
        }

        for field, replacement in fields.items():
            with self.subTest(field=field):
                prepared = self._prepared_commit(manager)
                prepared["revealBundle"] = dict(prepared["revealBundle"])
                prepared["revealBundle"][field] = replacement
                api = Mock()
                api.prepare_commit.return_value = prepared
                chain = Mock()
                args = build_parser().parse_args(
                    [
                        "commit",
                        "7",
                        "--solver",
                        SOLVER,
                        "--artifact-id",
                        ARTIFACT_ID,
                        "--solution-digest",
                        DIGEST,
                        "--private-key",
                        "0x" + "11" * 32,
                        "--send",
                    ]
                )
                with (
                    patch(
                        "threesat_cli.main.load_config",
                        return_value={"chain_id": 421614, "bounty_manager": manager},
                    ),
                    patch("threesat_cli.main.make_api", return_value=api),
                    patch("threesat_cli.main._synchronize_commit_bond", return_value=chain),
                    redirect_stdout(io.StringIO()),
                    self.assertRaisesRegex(RuntimeError, "reveal bundle"),
                ):
                    command_commit(args)
                chain.send_prepared_transaction.assert_not_called()

    def test_commit_rejects_tampered_target_calldata_and_extra_transactions(self) -> None:
        manager = "0x2222222222222222222222222222222222222222"
        mutations = (
            lambda prepared: prepared["transactions"][0].update(
                {"to": "0x3333333333333333333333333333333333333333"}
            ),
            lambda prepared: prepared["transactions"][0].update({"data": "0x1234"}),
            lambda prepared: prepared["transactions"].append(
                {
                    "label": "Unexpected call",
                    "functionName": "transfer",
                    "to": manager,
                    "data": "0x",
                    "value": "0",
                    "args": [],
                }
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                prepared = self._prepared_commit(manager)
                mutate(prepared)
                api = Mock()
                api.prepare_commit.return_value = prepared
                chain = Mock()
                args = build_parser().parse_args(
                    [
                        "commit",
                        "7",
                        "--solver",
                        SOLVER,
                        "--artifact-id",
                        ARTIFACT_ID,
                        "--solution-digest",
                        DIGEST,
                        "--private-key",
                        "0x" + "11" * 32,
                        "--send",
                    ]
                )
                with (
                    patch(
                        "threesat_cli.main.load_config",
                        return_value={"chain_id": 421614, "bounty_manager": manager},
                    ),
                    patch("threesat_cli.main.make_api", return_value=api),
                    patch("threesat_cli.main._synchronize_commit_bond", return_value=chain),
                    redirect_stdout(io.StringIO()),
                    self.assertRaisesRegex(RuntimeError, "transaction|calldata"),
                ):
                    command_commit(args)
                chain.send_prepared_transaction.assert_not_called()

    def test_commit_hash_matches_the_protocol_fixed_vector(self) -> None:
        self.assertEqual(
            compute_solution_commit_hash(
                chain_id=421614,
                bounty_manager="0x4444444444444444444444444444444444444444",
                bounty_id=42,
                solver=SOLVER,
                solution_kind=2,
                proof_format=2,
                solution_digest=DIGEST,
                salt=SALT,
            ),
            "0x5b071490eb66e47ffa263d2658481986253ce6f3fb11e79908e7dba50d52aeef",
        )

    def test_reveal_sends_artifact_id_to_the_api_but_not_to_the_transaction(self) -> None:
        prepared = {
            "bountyId": "7",
            "bountyCode": "SAT-TEST",
            "submissionId": "1",
            "solutionKindCode": "SAT",
            "proofFormatName": "None",
            "transactions": [
                {
                    "label": "Reveal solution",
                    "to": "0x2222222222222222222222222222222222222222",
                    "functionName": "revealSolution",
                    "args": ["7", "1", 1, 0, DIGEST, SALT],
                }
            ],
        }
        api = Mock()
        api.prepare_reveal.return_value = prepared
        args = argparse.Namespace(
            bundle=None,
            bounty="7",
            submission_id="1",
            artifact_id=ARTIFACT_ID,
            solution_digest=DIGEST,
            salt=SALT,
            kind="sat",
            proof_format="drat",
            send=False,
            private_key=None,
            json=False,
        )
        with (
            patch("threesat_cli.main.load_config", return_value={}),
            patch("threesat_cli.main.make_api", return_value=api),
            redirect_stdout(io.StringIO()),
        ):
            command_reveal(args)

        request = api.prepare_reveal.call_args.args[0]
        self.assertEqual(request["artifactId"], ARTIFACT_ID)
        self.assertEqual(prepared["transactions"][0]["args"], ["7", "1", 1, 0, DIGEST, SALT])

    def test_bounty_manager_abi_matches_the_digest_only_protocol(self) -> None:
        self.assertEqual(
            [item["name"] for item in abi_item("computeCommitHash")["inputs"]],
            ["bountyId", "solver", "solutionKind", "proofFormat", "solutionDigest", "salt"],
        )
        self.assertEqual(
            [item["name"] for item in abi_item("revealSolution")["inputs"]],
            ["bountyId", "submissionId", "solutionKind", "proofFormat", "solutionDigest", "salt"],
        )
        self.assertEqual(
            [item["name"] for item in abi_item("attest")["inputs"]],
            ["bountyId", "submissionId", "support"],
        )
        submission_fields = abi_item("getSubmission")["outputs"][0]["components"]
        self.assertNotIn("string", {field["type"] for field in submission_fields})
        revealed_fields = abi_item("SolutionRevealed", "event")["inputs"]
        self.assertNotIn("string", {field["type"] for field in revealed_fields})


if __name__ == "__main__":
    unittest.main()
