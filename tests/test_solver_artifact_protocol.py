from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from threesat_cli.chain import BOUNTY_MANAGER_ABI, compute_solution_commit_hash
from threesat_cli.main import (
    _prepare_commit_payload,
    _validated_solution_artifact,
    build_parser,
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
        prepared = {
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
            "revealBundle": {
                "bountyId": "7",
                "artifactId": ARTIFACT_ID,
                "solutionKind": 1,
                "proofFormat": 0,
                "solutionDigest": DIGEST,
                "salt": SALT,
                "commitHash": commit_hash,
            },
            "transactions": [
                {
                    "functionName": "commitSolution",
                    "args": ["7", commit_hash],
                }
            ],
        }
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
