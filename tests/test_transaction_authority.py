from __future__ import annotations

import argparse
import copy
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from eth_account import Account
from web3 import Web3

from threesat_cli.chain import (
    ChainClient,
    compute_solution_commit_hash,
    encode_approval_data,
    encode_commit_solution_data,
    encode_create_bounty_data,
    encode_reveal_solution_data,
)
from threesat_cli.main import (
    _assert_commit_binding,
    _assert_explicit_reveal_inputs,
    _assert_requested_bounty,
    _display_bounty_code,
    _issue_transactions,
    _reveal_solution_data,
    _synchronize_commit_bond,
    build_parser,
    command_commit,
    command_issue,
    command_reveal,
)


MANAGER = "0x2222222222222222222222222222222222222222"
PAYMENT_TOKEN = "0x3333333333333333333333333333333333333333"
OTHER_TOKEN = "0x4444444444444444444444444444444444444444"
PRIVATE_KEY = "0x" + "11" * 32
SOLVER = Account.from_key(PRIVATE_KEY).address
ARTIFACT_ID = "artifact-" + "ab" * 24
SOLUTION_DIGEST = "0x" + "22" * 32
SALT = "0x" + "33" * 32


def protocol_config() -> dict:
    return {
        "api_url": "https://example.test",
        "rpc_url": "https://rpc.example.test",
        "chain_id": 421614,
        "bounty_manager": MANAGER,
        "tokens": {
            "USDC": {
                "symbol": "USDC",
                "address": PAYMENT_TOKEN,
                "decimals": 6,
            }
        },
    }


def prefixed_keccak(payload: bytes) -> str:
    digest = Web3.keccak(payload).hex()
    return digest if digest.startswith("0x") else f"0x{digest}"


class TransactionAuthorityTests(unittest.TestCase):
    def _run_issue(self, mutate, chain: Mock | None = None) -> tuple[Mock, Mock]:
        config = protocol_config()
        token = config["tokens"]["USDC"]
        instance_payload = b"p cnf 1 1\n1 0\n"
        metadata_payload = b"{}"
        instance_digest = prefixed_keccak(instance_payload)
        metadata_digest = prefixed_keccak(metadata_payload)
        api = Mock()
        api.upload_file.side_effect = [
            {"ref": "r2://instance", "digest": instance_digest},
            {"ref": "r2://metadata", "digest": metadata_digest},
        ]
        api.build_metadata.return_value = {"payload": "{}", "fileName": "metadata.json"}

        def prepare(payload: dict) -> dict:
            transactions = _issue_transactions(
                config=config,
                token=token,
                instance_ref=str(payload["instanceRef"]),
                instance_digest=str(payload["instanceDigest"]),
                metadata_ref=str(payload["metadataRef"]),
                metadata_digest=str(payload["metadataDigest"]),
                reward=1_000_000,
                posting_fee=0,
                verifier_reward_pool=20_000,
                commit_window=3_600,
                reveal_window=3_600,
                verification_window=3_600,
                verifier_quorum=1,
            )
            mutate(transactions)
            return {"transactions": transactions}

        api.prepare_create_bounty.side_effect = prepare
        chain = chain or Mock()
        chain.verifier_reward_pool_for.return_value = 20_000
        chain.verifier_reward_bps.return_value = 200
        chain.send_prepared_transaction.return_value = {"hash": "0x1", "status": 1, "gasUsed": 1}

        with tempfile.TemporaryDirectory() as temporary_directory:
            instance = Path(temporary_directory, "problem.cnf")
            instance.write_bytes(instance_payload)
            args = build_parser().parse_args(
                [
                    "issue",
                    str(instance),
                    "--reward",
                    "1",
                    "--send",
                    "--private-key",
                    PRIVATE_KEY,
                ]
            )
            with (
                patch("threesat_cli.main.load_config", return_value=config),
                patch("threesat_cli.main.make_api", return_value=api),
                patch("threesat_cli.main.make_chain", return_value=chain),
                redirect_stdout(StringIO()),
            ):
                command_issue(args)
        return api, chain

    def test_issue_validates_the_entire_batch_before_sending_the_approval(self) -> None:
        mutations = (
            lambda txs: txs[1].update({"to": OTHER_TOKEN}),
            lambda txs: txs[1].update({"data": "0x1234"}),
            lambda txs: txs[1].update({"value": "1"}),
            lambda txs: txs.append(copy.deepcopy(txs[1])),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                chain = Mock()
                with self.assertRaisesRegex(RuntimeError, "transaction|exactly"):
                    self._run_issue(mutate, chain)
                chain.send_prepared_transaction.assert_not_called()

    def test_issue_broadcasts_only_locally_reconstructed_transactions(self) -> None:
        def change_untrusted_labels(transactions: list[dict]) -> None:
            transactions[0]["label"] = "Server-controlled approval label"
            transactions[1]["label"] = "Server-controlled create label"

        _api, chain = self._run_issue(change_untrusted_labels)
        sent = [call.args[0] for call in chain.send_prepared_transaction.call_args_list]
        self.assertEqual([transaction["label"] for transaction in sent], ["Approve bounty escrow", "Create bounty"])
        self.assertTrue(all(int(transaction["value"]) == 0 for transaction in sent))

    @staticmethod
    def _prepared_reveal() -> dict:
        return {
            "chainId": 421614,
            "bountyManager": MANAGER,
            "bountyId": "7",
            "bountyCode": _display_bounty_code(7),
            "submissionId": "1",
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "solutionKindCode": "SAT",
            "proofFormat": 0,
            "proofFormatName": "None",
            "transactions": [
                {
                    "label": "Server-controlled reveal label",
                    "contract": "BountyManager",
                    "functionName": "revealSolution",
                    "to": MANAGER,
                    "data": _reveal_solution_data("7", "1", 1, 0, SOLUTION_DIGEST, SALT),
                    "value": "0",
                    "args": ["7", "1", 1, 0, SOLUTION_DIGEST, SALT],
                }
            ],
        }

    @staticmethod
    def _reveal_args() -> argparse.Namespace:
        return build_parser().parse_args(
            [
                "reveal",
                "--bounty",
                "7",
                "--submission-id",
                "1",
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                SOLUTION_DIGEST,
                "--salt",
                SALT,
                "--send",
                "--private-key",
                PRIVATE_KEY,
            ]
        )

    def test_reveal_rejects_tampering_and_extra_transactions_before_broadcast(self) -> None:
        mutations = (
            lambda prepared: prepared["transactions"][0].update({"to": OTHER_TOKEN}),
            lambda prepared: prepared["transactions"][0].update({"data": "0x1234"}),
            lambda prepared: prepared["transactions"][0].update({"value": "1"}),
            lambda prepared: prepared["transactions"].append(copy.deepcopy(prepared["transactions"][0])),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                prepared = self._prepared_reveal()
                mutate(prepared)
                api = Mock()
                api.prepare_reveal.return_value = prepared
                chain = Mock()
                with (
                    patch("threesat_cli.main.load_config", return_value=protocol_config()),
                    patch("threesat_cli.main.make_api", return_value=api),
                    patch("threesat_cli.main.make_chain", return_value=chain),
                    redirect_stdout(StringIO()),
                    self.assertRaisesRegex(RuntimeError, "transaction|exactly"),
                ):
                    command_reveal(self._reveal_args())
                chain.send_prepared_transaction.assert_not_called()

    def test_reveal_checks_the_onchain_commit_and_sends_the_local_transaction(self) -> None:
        prepared = self._prepared_reveal()
        api_transaction = prepared["transactions"][0]
        api = Mock()
        api.prepare_reveal.return_value = prepared
        commit_hash = compute_solution_commit_hash(
            chain_id=421614,
            bounty_manager=MANAGER,
            bounty_id=7,
            solver=SOLVER,
            solution_kind=1,
            proof_format=0,
            solution_digest=SOLUTION_DIGEST,
            salt=SALT,
        )
        chain = Mock()
        chain.submission_identity.return_value = (SOLVER, commit_hash)
        chain.send_prepared_transaction.return_value = {"hash": "0x1", "status": 1, "gasUsed": 1}
        with (
            patch("threesat_cli.main.load_config", return_value=protocol_config()),
            patch("threesat_cli.main.make_api", return_value=api),
            patch("threesat_cli.main.make_chain", return_value=chain),
            redirect_stdout(StringIO()),
        ):
            command_reveal(self._reveal_args())

        sent = chain.send_prepared_transaction.call_args.args[0]
        self.assertIsNot(sent, api_transaction)
        self.assertEqual(sent["label"], "Reveal solution")
        self.assertEqual(sent["to"].lower(), MANAGER.lower())
        self.assertEqual(sent["data"].lower(), api_transaction["data"].lower())
        self.assertEqual(int(sent["value"]), 0)

    def test_reveal_rejects_explicit_fields_that_conflict_with_a_bundle(self) -> None:
        payload = {
            "bounty": "7",
            "submissionId": "1",
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "proofFormat": 0,
            "solutionDigest": SOLUTION_DIGEST,
            "salt": SALT,
        }
        base_args = argparse.Namespace(
            bounty=None,
            submission_id=None,
            artifact_id=None,
            solution_digest=None,
            salt=None,
            kind=None,
            proof_format=None,
        )
        mutations = {
            "bounty": "8",
            "submission_id": "2",
            "artifact_id": "artifact-" + "cd" * 24,
            "solution_digest": "0x" + "44" * 32,
            "salt": "0x" + "55" * 32,
            "kind": "unsat",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                args = copy.deepcopy(base_args)
                setattr(args, field, value)
                with self.assertRaises(RuntimeError):
                    _assert_explicit_reveal_inputs(args, payload, self._prepared_reveal())

        proof_args = copy.deepcopy(base_args)
        proof_args.proof_format = "drat"
        unsat_payload = {**payload, "solutionKind": 2, "proofFormat": 2}
        with self.assertRaisesRegex(RuntimeError, "conflict"):
            _assert_explicit_reveal_inputs(proof_args, unsat_payload, self._prepared_reveal())

        equivalent_args = copy.deepcopy(base_args)
        equivalent_args.bounty = _display_bounty_code(7)
        equivalent_args.submission_id = "01"
        equivalent_args.artifact_id = ARTIFACT_ID
        equivalent_args.solution_digest = SOLUTION_DIGEST.upper().replace("0X", "0x")
        equivalent_args.salt = SALT.upper().replace("0X", "0x")
        equivalent_args.kind = "SAT"
        equivalent_args.proof_format = "DRAT"
        _assert_explicit_reveal_inputs(equivalent_args, payload, self._prepared_reveal())

    def test_reveal_rejects_a_bundle_conflict_before_api_registration(self) -> None:
        conflicting_artifact = "artifact-" + "cd" * 24
        args = build_parser().parse_args(
            [
                "reveal",
                "--bundle",
                "ignored.json",
                "--submission-id",
                "1",
                "--artifact-id",
                conflicting_artifact,
            ]
        )
        bundle = {
            "bountyId": "7",
            "submissionId": "1",
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "proofFormat": 0,
            "solutionDigest": SOLUTION_DIGEST,
            "salt": SALT,
        }
        api = Mock()
        with (
            patch("threesat_cli.main.load_config", return_value=protocol_config()),
            patch("threesat_cli.main.make_api", return_value=api),
            patch("threesat_cli.main._load_reveal_bundle", return_value=bundle),
            self.assertRaisesRegex(RuntimeError, "conflict"),
        ):
            command_reveal(args)
        api.prepare_reveal.assert_not_called()

    def test_commit_rejects_a_private_key_that_is_not_the_declared_solver_before_api_use(self) -> None:
        api = Mock()
        args = build_parser().parse_args(
            [
                "commit",
                "7",
                "--solver",
                OTHER_TOKEN,
                "--artifact-id",
                ARTIFACT_ID,
                "--solution-digest",
                SOLUTION_DIGEST,
                "--send",
                "--private-key",
                PRIVATE_KEY,
            ]
        )
        with (
            patch("threesat_cli.main.load_config", return_value=protocol_config()),
            patch("threesat_cli.main.make_api", return_value=api),
            self.assertRaisesRegex(RuntimeError, "private key"),
        ):
            command_commit(args)
        api.prepare_commit.assert_not_called()

    def test_commit_rejects_an_api_swapped_bond_token(self) -> None:
        prepared = {
            "bountyManager": MANAGER,
            "bountyId": "7",
            "bondToken": OTHER_TOKEN,
            "transactions": [],
        }
        chain = Mock()
        chain.bounty_payment_token.return_value = PAYMENT_TOKEN
        with (
            patch("threesat_cli.main.make_chain", return_value=chain),
            self.assertRaisesRegex(RuntimeError, "payment token"),
        ):
            _synchronize_commit_bond(prepared, protocol_config())
        chain.bounty_solver_bond.assert_not_called()

    def test_commit_rejects_an_api_swapped_explicit_salt(self) -> None:
        replacement_salt = "0x" + "55" * 32
        prepared = {
            "chainId": 421614,
            "bountyManager": MANAGER,
            "bountyId": "7",
            "solver": SOLVER,
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "proofFormat": 0,
            "solutionDigest": SOLUTION_DIGEST,
            "salt": replacement_salt,
            "commitHash": compute_solution_commit_hash(
                chain_id=421614,
                bounty_manager=MANAGER,
                bounty_id=7,
                solver=SOLVER,
                solution_kind=1,
                proof_format=0,
                solution_digest=SOLUTION_DIGEST,
                salt=replacement_salt,
            ),
        }
        payload = {
            "bounty": "7",
            "solver": SOLVER,
            "artifactId": ARTIFACT_ID,
            "solutionKind": 1,
            "proofFormat": 0,
            "solutionDigest": SOLUTION_DIGEST,
            "salt": SALT,
        }
        with self.assertRaisesRegex(RuntimeError, "explicitly requested salt"):
            _assert_commit_binding(prepared, payload, protocol_config())

    def test_locally_encoded_transaction_selectors_match_the_contract_abi(self) -> None:
        self.assertTrue(encode_approval_data(MANAGER, 1).startswith("0x095ea7b3"))
        self.assertTrue(encode_commit_solution_data(7, "0x" + "11" * 32).startswith("0x3f9a29e9"))
        self.assertTrue(
            encode_reveal_solution_data(
                bounty_id=7,
                submission_id=1,
                solution_kind=1,
                proof_format=0,
                solution_digest=SOLUTION_DIGEST,
                salt=SALT,
            ).startswith("0x9f275ff5")
        )
        self.assertTrue(
            encode_create_bounty_data(
                payment_token=PAYMENT_TOKEN,
                instance_ref="r2://instance",
                instance_digest="0x" + "11" * 32,
                metadata_ref="r2://metadata",
                metadata_digest="0x" + "22" * 32,
                reward=1,
                posting_fee=2,
                commit_window=3_600,
                reveal_window=3_600,
                verification_window=3_600,
                verifier_quorum=1,
            ).startswith("0xbd238ab4")
        )

    def test_bounty_code_binding_matches_the_cross_language_vectors(self) -> None:
        vectors = {
            1: ("SAT-YKSF-Z73V-QB7D", "SAT-YKSF-Z73V"),
            7: ("SAT-99CP-AFP4-9B7F", "SAT-99CP-AFP4"),
            42: ("SAT-UJR3-AEJ9-YQA3", "SAT-UJR3-AEJ9"),
        }
        for bounty_id, (current, legacy) in vectors.items():
            with self.subTest(bounty_id=bounty_id):
                self.assertEqual(_display_bounty_code(bounty_id), current)
                self.assertEqual(_display_bounty_code(bounty_id, 8), legacy)
                for requested in (str(bounty_id), f"00{bounty_id}", current.lower(), current.replace("-", ""), legacy):
                    _assert_requested_bounty(requested, {"bountyId": str(bounty_id)})

        with self.assertRaisesRegex(RuntimeError, "requested bounty"):
            _assert_requested_bounty("8", {"bountyId": "7"})
        with self.assertRaisesRegex(RuntimeError, "bounty code"):
            _assert_requested_bounty("SAT-YKSF-Z73V-QB7D", {"bountyId": "7"})


if __name__ == "__main__":
    unittest.main()
