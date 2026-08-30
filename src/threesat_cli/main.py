from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak
from eth_account import Account
from web3 import Web3

from .api import MAXIMUM_INSTANCE_UPLOAD_BYTES, ProtocolApi
from .chain import (
    ACCESS_STATUS_DISABLED,
    ACCESS_STATUS_PRICED,
    ACCESS_STATUS_PUBLIC,
    ACCESS_STATUS_UNCONFIGURED,
    ChainClient,
    LEGACY_ACCESS_CONTROLLER_CHAIN_ID,
    LEGACY_ARTIFACT_ACCESS_CONTROLLER,
    LEGACY_SOLVER_BOND_BOUNTY_MANAGER,
    LEGACY_SOLVER_BOND_CHAIN_ID,
    compute_solution_commit_hash,
    sign_access_message,
    sign_solution_upload_message,
)
from .config import (
    CONFIG_PATH,
    init_config,
    load_config,
    private_key_from_args,
    save_config,
    set_config_value,
    token_by_address,
    token_by_symbol,
)
from .dimacs_parser_core import (
    InvalidDimacsError,
    load_dimacs_cnf_file,
    parse_dimacs_cnf_bytes,
)
from .formatting import (
    filename_from_content_disposition,
    format_token_amount,
    normalize_proof_format,
    normalize_solution_kind,
    parse_token_amount,
    print_json,
    proof_format_label,
    short_address,
    solution_kind_label,
    validate_dimacs_cnf_bytes,
    validate_unit_clause_assignment,
    write_bytes,
)

MINIMUM_BOUNTY_WINDOW_HOURS = 1
MINIMUM_BOUNTY_WINDOW_SECONDS = MINIMUM_BOUNTY_WINDOW_HOURS * 60 * 60
REQUIRED_VERIFIER_QUORUM = 1
MAXIMUM_PROOF_UPLOAD_BYTES = 100 * 1024 * 1024
MAXIMUM_SAT_SOLUTION_UPLOAD_BYTES = 25 * 1024 * 1024
MAXIMUM_MATCHED_CNF_BYTES = 25 * 1024 * 1024
DIRECT_MATCHED_CNF_UPLOAD_THRESHOLD_BYTES = int(3.5 * 1024 * 1024)
MAXIMUM_ARTIFACT_ID_BYTES = 256
DEFAULT_REVEAL_BUNDLE_DIRECTORY = Path("data") / "reveal-bundles"


def make_api(config: dict[str, Any]) -> ProtocolApi:
    return ProtocolApi(config["api_url"])


def make_chain(config: dict[str, Any]) -> ChainClient:
    return ChainClient(config["rpc_url"], int(config["chain_id"]))


def require_private_key(args: argparse.Namespace) -> str:
    key = private_key_from_args(getattr(args, "private_key", None))
    if not key:
        raise RuntimeError("Private key required. Pass --private-key or set 3SAT_PRIVATE_KEY.")
    return key


def maybe_json(args: argparse.Namespace, payload: Any) -> bool:
    if getattr(args, "json", False):
        print_json(payload)
        return True
    return False


def print_check(label: str, ok: bool, detail: str = "") -> None:
    status = "OK" if ok else "FAIL"
    suffix = f" - {detail}" if detail else ""
    print(f"[{status}] {label}{suffix}")


def human_token(config: dict[str, Any], token_address: str, amount: int | str) -> str:
    token = token_by_address(config, token_address)
    return format_token_amount(amount, int(token["decimals"]), token["symbol"])


def print_prepared_transactions(transactions: list[dict[str, Any]]) -> None:
    for index, tx in enumerate(transactions, start=1):
        print(f"{index}. {tx['label']}")
        print(f"   To:   {tx['to']}")
        print(f"   Func: {tx.get('functionName', '-')}")


def command_config(args: argparse.Namespace) -> None:
    if args.config_command == "init":
        path = init_config(force=args.force)
        print(f"Config initialized: {path}")
        return
    if args.config_command == "show":
        config = load_config()
        print_json(config)
        print(f"\nConfig path: {CONFIG_PATH}")
        return
    if args.config_command == "set":
        path = set_config_value(args.key, args.value)
        print(f"Updated {args.key} in {path}")
        return
    raise RuntimeError("Unknown config command.")


def command_standardize(args: argparse.Namespace) -> None:
    payload, _parsed = load_dimacs_cnf_file(args.cnf)
    api = make_api(load_config())
    result = api.standardize(payload, file_name=Path(args.cnf).name)
    if maybe_json(args, result):
        return
    print("CNF standardized")
    print(f"Variables: {result.get('variables')}")
    print(f"Clauses:   {result.get('clauses')}")
    print(f"Digest:    {result.get('canonicalDigest')}")
    if args.output:
        write_bytes(args.output, result["canonicalText"].encode("utf-8"))
        print(f"Wrote:     {args.output}")
    elif args.print_text:
        print("\n" + result["canonicalText"])


def command_search(args: argparse.Namespace) -> None:
    payload, _parsed = load_dimacs_cnf_file(args.cnf)
    api = make_api(load_config())
    result = api.search(payload, file_name=Path(args.cnf).name)
    query = result.get("query") if isinstance(result, dict) else None
    returned_raw_digest = (
        str(query.get("rawDigest") or "") if isinstance(query, dict) else ""
    )
    expected_raw_digest = _keccak_hex(payload)
    if (
        re.fullmatch(r"0x[0-9a-fA-F]{64}", returned_raw_digest) is None
        or returned_raw_digest.lower() != expected_raw_digest.lower()
    ):
        raise RuntimeError(
            "Search response raw digest does not match the locally validated CNF bytes."
        )
    if maybe_json(args, result):
        return
    print(result.get("databaseStatusLabel", "Search completed."))
    print(f"CNF: {query.get('variables', '-')} variables / {query.get('clauses', '-')} clauses")
    print(f"Raw digest: {query.get('rawDigest')}")
    print(f"Format-normalized digest: {query.get('canonicalDigest')}")
    print(f"Variable-normalized digest: {query.get('structureDigest')}")
    bounties = result.get("bounties") or []
    if not bounties:
        print("No matching bounties.")
        return
    print("\nMatching bounties:")
    for bounty in bounties:
        status = "finalized" if bounty.get("finalized") else "open"
        print(
            f"- {bounty.get('bountyCode')} "
            f"({status}, submissions {bounty.get('submissionCount')}, verified results {bounty.get('verifiedAnswerCount')})"
        )
        for answer in bounty.get("answers") or []:
            print(
                f"  submission #{answer.get('submissionId')}: "
                f"{answer.get('solutionKindName')} / {answer.get('proofFormatName')} / {answer.get('stateLabel')}"
            )


def command_marketplace(args: argparse.Namespace) -> None:
    api = make_api(load_config())
    limit = max(1, args.limit)
    offset = max(0, args.offset)
    result = api.marketplace(sync=args.sync, limit=limit, offset=offset)
    if maybe_json(args, result):
        return
    status = result.get("status", {})
    bounties = result.get("bounties") or []
    pagination = result.get("pagination") or {}
    total = pagination.get("total", status.get("cachedBounties", "?"))
    shown_bounties = bounties if pagination else bounties[offset : offset + limit]
    print(f"Marketplace: {total} cached bounties")
    print(f"Showing {len(shown_bounties)} bounties")
    print(f"Indexer storage: {status.get('storage')} / last block {status.get('lastIndexedBlock')}")
    for bounty in shown_bounties:
        reward = bounty.get("reward", "-")
        code = bounty.get("bountyCode") or bounty.get("bountyId")
        state = bounty.get("status") or bounty.get("statusLabel") or ("finalized" if bounty.get("finalized") else "open")
        print(f"- {code}: reward {reward}, {state}")
    if pagination.get("hasMore") or (not pagination and offset + len(shown_bounties) < len(bounties)):
        print(f"More bounties available. Use --offset {offset + len(shown_bounties)} to load the next page.")


def command_bounty(args: argparse.Namespace) -> None:
    api = make_api(load_config())
    result = api.bounty(args.bounty)
    if maybe_json(args, result):
        return
    bounty = result["bounty"]
    print(f"Bounty: {result['bountyCode']} (internal id {result['bountyId']})")
    print(f"Issuer: {bounty['issuer']}")
    print(f"Payment token: {bounty['paymentToken']}")
    print(f"Reward: {bounty['reward']}")
    print(f"Verifier reward pool: {bounty['verifierRewardPool']}")
    print(f"Finalized: {bounty['finalized']}")
    print(f"Verifier quorum: {bounty['verifierQuorum']}")
    print(f"Submissions: {bounty['submissionCount']}")
    for submission in result.get("submissions") or []:
        print(
            f"- submission #{submission['submissionId']}: {submission['stateLabel']}, "
            f"for {submission['forVotes']} / against {submission['againstVotes']}, "
            f"{submission['solutionKindName']} {submission['proofFormatName']}"
        )


def command_balance(args: argparse.Namespace) -> None:
    config = load_config()
    chain = make_chain(config)
    address = args.address
    if not address:
        key = require_private_key(args)
        address = Account.from_key(key).address
    if maybe_json(
        args,
        {
            "address": address,
            "nativeWei": str(chain.native_balance(address)),
            "tokens": {
                symbol: str(chain.token_balance(token["address"], address))
                for symbol, token in config.get("tokens", {}).items()
            },
        },
    ):
        return
    print(f"Address: {address}")
    print(f"Native balance: {chain.native_balance(address)} wei")
    for symbol, token in config.get("tokens", {}).items():
        balance = chain.token_balance(token["address"], address)
        print(f"{token['symbol']} balance: {format_token_amount(balance, int(token['decimals']), token['symbol'])}")


def command_tokens(args: argparse.Namespace) -> None:
    config = load_config()
    chain: ChainClient | None = None
    if args.onchain:
        chain = make_chain(config)
    if maybe_json(args, {"chainId": config["chain_id"], "chainName": config["chain_name"], "tokens": config.get("tokens", {})}):
        return
    print(f"Network: {config['chain_name']} ({config['chain_id']})")
    print(f"RPC:     {config['rpc_url']}")
    for key, token in config.get("tokens", {}).items():
        print(f"\n{key}")
        print(f"  Symbol:   {token['symbol']}")
        print(f"  Address:  {token['address']}")
        print(f"  Decimals: {token['decimals']}")
        if chain:
            try:
                info = chain.token_info(token["address"])
                code_size = chain.contract_code_size(token["address"])
                print(f"  On-chain: {info['symbol']} / decimals {info['decimals']} / code {code_size} bytes")
            except Exception as exc:
                print(f"  On-chain check failed: {exc}")


def command_doctor(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    failures = 0

    print("3SAT CLI doctor")
    print(f"Config: {CONFIG_PATH}")

    try:
        indexer = api.get("/api/protocol/indexer")
        print_check("API", True, f"{config['api_url']} / storage {indexer.get('storage')}")
    except Exception as exc:
        print_check("API", False, str(exc))
        failures += 1

    try:
        marketplace = api.marketplace(sync=False)
        status = marketplace.get("status") or {}
        print_check("Marketplace API", True, f"{status.get('cachedBounties', len(marketplace.get('bounties') or []))} cached bounties")
    except Exception as exc:
        print_check("Marketplace API", False, str(exc))
        failures += 1

    try:
        chain = make_chain(config)
        print_check("RPC", True, f"connected chain id {chain.chain_id}")
    except Exception as exc:
        print_check("RPC", False, str(exc))
        raise SystemExit(1)

    for label, address in [
        ("BountyManager", config.get("bounty_manager")),
        ("ArtifactAccessController", config.get("artifact_access_controller")),
    ]:
        try:
            code_size = chain.contract_code_size(address)
            ok = code_size > 0
            print_check(label, ok, f"{address} / code {code_size} bytes")
            failures += 0 if ok else 1
        except Exception as exc:
            print_check(label, False, str(exc))
            failures += 1

    for symbol, token in config.get("tokens", {}).items():
        try:
            info = chain.token_info(token["address"])
            code_size = chain.contract_code_size(token["address"])
            ok = code_size > 0
            print_check(
                f"Token {symbol}",
                ok,
                f"{info['symbol']} decimals {info['decimals']} / {token['address']} / code {code_size} bytes",
            )
            failures += 0 if ok else 1
        except Exception as exc:
            print_check(f"Token {symbol}", False, str(exc))
            failures += 1

    address = args.address
    key = private_key_from_args(args.private_key)
    if not address and key:
        address = Account.from_key(key).address
    if address:
        print(f"\nWallet: {address}")
        try:
            print_check("Native balance", True, f"{chain.native_balance(address)} wei")
        except Exception as exc:
            print_check("Native balance", False, str(exc))
            failures += 1
        for symbol, token in config.get("tokens", {}).items():
            try:
                balance = chain.token_balance(token["address"], address)
                print_check(
                    f"{token['symbol']} balance",
                    True,
                    format_token_amount(balance, int(token["decimals"]), token["symbol"]),
                )
            except Exception as exc:
                print_check(f"{symbol} balance", False, str(exc))
                failures += 1

    if failures:
        raise SystemExit(1)
    print("\nDoctor completed with no failures.")


def command_issue(args: argparse.Namespace) -> None:
    if args.quorum != REQUIRED_VERIFIER_QUORUM:
        raise RuntimeError(
            f"Verifier quorum is temporarily fixed at {REQUIRED_VERIFIER_QUORUM}; "
            f"--quorum must be {REQUIRED_VERIFIER_QUORUM}."
        )

    instance_path = Path(args.cnf)
    if not instance_path.is_file():
        raise RuntimeError(f"CNF file not found: {instance_path}")
    try:
        cnf_payload, _parsed_cnf = load_dimacs_cnf_file(
            instance_path,
            {"max_input_bytes": MAXIMUM_INSTANCE_UPLOAD_BYTES},
        )
    except InvalidDimacsError as error:
        if "byte resource limit" in str(error):
            raise RuntimeError("Instance CNF files must be 4 MiB or smaller.") from error
        raise

    config = load_config()
    api = make_api(config)
    token = token_by_symbol(config, args.token)
    if len(args.description or "") > 200:
        raise SystemExit("Task description must be 200 characters or fewer.")

    cnf_summary = validate_dimacs_cnf_bytes(cnf_payload)
    commit_seconds = int(round(float(args.open_hours) * 3600))
    reveal_seconds = int(round(float(args.reveal_hours) * 3600))
    verify_seconds = int(round(float(args.verify_hours) * 3600))
    if min(commit_seconds, reveal_seconds, verify_seconds) < MINIMUM_BOUNTY_WINDOW_SECONDS:
        raise RuntimeError(f"All timing windows must be at least {MINIMUM_BOUNTY_WINDOW_HOURS} hours.")
    reward_raw = parse_token_amount(args.reward, int(token["decimals"]))
    posting_fee_raw = 0 if str(args.posting_fee).strip() in {"", "0"} else parse_token_amount(args.posting_fee, int(token["decimals"]))
    verifier_pool_raw: int | None = None
    verifier_reward_bps: int | None = None
    prepared_dry_run: dict[str, Any] | None = None
    try:
        prepared_dry_run = api.prepare_create_bounty(
            {
                "paymentToken": token["address"],
                "instanceRef": f"dry-run://{instance_path.name}",
                "instanceDigest": cnf_summary["rawDigest"],
                "metadataRef": "dry-run://metadata.json",
                "metadataDigest": cnf_summary["rawDigest"],
                "reward": args.reward,
                "postingFee": args.posting_fee,
                "commitWindowSeconds": str(commit_seconds),
                "revealWindowSeconds": str(reveal_seconds),
                "verificationWindowSeconds": str(verify_seconds),
                "verifierQuorum": str(args.quorum),
            }
        )
        verifier_pool_raw = int(prepared_dry_run["verifierRewardPool"])
        verifier_reward_bps = int(prepared_dry_run["verifierRewardBps"])
    except Exception:
        prepared_dry_run = None
    try:
        if verifier_pool_raw is None:
            chain = make_chain(config)
            verifier_pool_raw = chain.verifier_reward_pool_for(config["bounty_manager"], reward_raw)
            verifier_reward_bps = chain.verifier_reward_bps(config["bounty_manager"])
    except Exception:
        pass

    total_preview = reward_raw + posting_fee_raw + (verifier_pool_raw or 0)
    dry_run_payload = {
        "cnf": str(instance_path),
        "variables": cnf_summary["variables"],
        "clauses": cnf_summary["clauses"],
        "rawDigest": cnf_summary["rawDigest"],
        "paymentToken": token["address"],
        "paymentSymbol": token["symbol"],
        "reward": str(reward_raw),
        "postingFee": str(posting_fee_raw),
        "verifierRewardPool": str(verifier_pool_raw) if verifier_pool_raw is not None else None,
        "verifierRewardBps": verifier_reward_bps,
        "totalEscrow": str(total_preview) if verifier_pool_raw is not None else None,
        "commitWindowSeconds": str(commit_seconds),
        "revealWindowSeconds": str(reveal_seconds),
        "verificationWindowSeconds": str(verify_seconds),
        "verifierQuorum": args.quorum,
    }
    if args.dry_run:
        if maybe_json(args, dry_run_payload):
            return
        print("Issue dry run")
        print(f"CNF: {cnf_summary['variables']} variables / {cnf_summary['clauses']} clauses")
        print(f"Raw digest: {cnf_summary['rawDigest']}")
        print(f"Payment asset: {token['symbol']} ({token['address']})")
        print(f"Reward: {format_token_amount(reward_raw, int(token['decimals']), token['symbol'])}")
        if verifier_pool_raw is not None:
            print(
                f"Verifier pool: {format_token_amount(verifier_pool_raw, int(token['decimals']), token['symbol'])}"
                + (f" ({verifier_reward_bps / 100:.2f}% of reward)" if verifier_reward_bps is not None else "")
            )
            print(f"Posting fee: {format_token_amount(posting_fee_raw, int(token['decimals']), token['symbol'])}")
            print(f"Total escrow: {format_token_amount(total_preview, int(token['decimals']), token['symbol'])}")
        else:
            print("Verifier pool: unavailable because chain/RPC check failed.")
        print(f"Open solving window: {commit_seconds} seconds")
        print(f"Reveal deadline after commit: {reveal_seconds} seconds")
        print(f"Verification window: {verify_seconds} seconds")
        print(f"Verifier quorum: {args.quorum}")
        print("No files uploaded and no transactions prepared.")
        return

    print(f"Uploading instance: {instance_path}")
    instance = api.upload_file(
        "instance",
        instance_path,
        content=cnf_payload,
        content_type="text/plain",
    )
    uploaded_instance_digest = (
        str(instance.get("digest") or "") if isinstance(instance, dict) else ""
    )
    if (
        re.fullmatch(r"0x[0-9a-fA-F]{64}", uploaded_instance_digest) is None
        or uploaded_instance_digest.lower() != cnf_summary["rawDigest"].lower()
    ):
        raise RuntimeError(
            "Uploaded instance digest does not match the locally validated CNF bytes."
        )
    print(f"Instance uploaded. Digest: {uploaded_instance_digest}")

    metadata_input = {
        "title": args.title,
        "description": args.description or "",
        "instanceRef": instance["ref"],
        "instanceHash": instance["digest"],
        "reward": args.reward,
        "postingFee": args.posting_fee,
        "commitWindowHours": str(args.open_hours),
        "revealWindowHours": str(args.reveal_hours),
        "verificationWindowHours": str(args.verify_hours),
        "commitWindowSeconds": str(commit_seconds),
        "revealWindowSeconds": str(reveal_seconds),
        "verificationWindowSeconds": str(verify_seconds),
        "verifierQuorum": str(args.quorum),
        "paymentToken": token["address"],
        "paymentSymbol": token["symbol"],
        "paymentDecimals": token["decimals"],
    }
    metadata = api.build_metadata(metadata_input)
    metadata_bytes = metadata["payload"].encode("utf-8")
    metadata_name = metadata.get("fileName") or f"{instance_path.stem}.metadata.json"
    print(f"Uploading metadata: {metadata_name}")
    metadata_upload = api.upload_file(
        "metadata",
        Path(metadata_name),
        content=metadata_bytes,
        file_name=metadata_name,
        content_type="application/json",
    )
    print(f"Metadata uploaded. Digest: {metadata_upload['digest']}")

    prepared = api.prepare_create_bounty(
        {
            "paymentToken": token["address"],
            "instanceRef": instance["ref"],
            "instanceDigest": instance["digest"],
            "metadataRef": metadata_upload["ref"],
            "metadataDigest": metadata_upload["digest"],
            "reward": args.reward,
            "postingFee": args.posting_fee,
            "commitWindowSeconds": str(commit_seconds),
            "revealWindowSeconds": str(reveal_seconds),
            "verificationWindowSeconds": str(verify_seconds),
            "verifierQuorum": str(args.quorum),
        }
    )
    if maybe_json(args, prepared):
        return

    print("\nPrepared bounty creation")
    print(f"Payment asset: {prepared['paymentSymbol']}")
    print(f"Reward: {format_token_amount(reward_raw, int(token['decimals']), token['symbol'])}")
    print(
        f"Verifier pool: {format_token_amount(prepared['verifierRewardPool'], int(token['decimals']), token['symbol'])}"
        f" ({prepared.get('verifierRewardBps', 0) / 100:.2f}% of reward)"
    )
    print(f"Posting fee: {format_token_amount(posting_fee_raw, int(token['decimals']), token['symbol'])}")
    print(f"Total escrow: {format_token_amount(prepared['escrowAmount'], int(token['decimals']), token['symbol'])}")
    print_prepared_transactions(prepared["transactions"])

    if not args.send:
        print("\nFiles were uploaded and transactions were prepared, but nothing was broadcast.")
        print("Use --dry-run next time if you want checks without uploading artifacts.")
        print("Re-run with --send to submit transactions.")
        return

    key = require_private_key(args)
    chain = make_chain(config)
    for tx in prepared["transactions"]:
        print(f"Sending {tx['label']}...")
        receipt = chain.send_prepared_transaction(tx, key)
        print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
        if receipt["status"] != 1:
            raise RuntimeError(f"{tx['label']} reverted.")
    try:
        api.marketplace(sync=True)
    except Exception:
        pass
    print("Bounty submitted. Refresh marketplace/search to see the new bounty.")


def command_upload_solution(args: argparse.Namespace) -> None:
    solution_path = Path(args.solution)
    if not solution_path.is_file():
        raise RuntimeError(f"Solution file not found: {solution_path}")
    solution_kind = normalize_solution_kind(args.kind)
    proof_format = normalize_proof_format(args.proof_format, solution_kind)
    if solution_kind == 1:
        try:
            solution_payload, parsed_solution = load_dimacs_cnf_file(
                solution_path,
                {"max_input_bytes": MAXIMUM_SAT_SOLUTION_UPLOAD_BYTES},
            )
        except InvalidDimacsError as error:
            if "byte resource limit" in str(error):
                raise RuntimeError("SAT solution files must be 25 MiB or smaller.") from error
            raise
        validate_unit_clause_assignment(parsed_solution)
        solution_size = len(solution_payload)
        digest = _keccak_hex(solution_payload)
    else:
        solution_size = solution_path.stat().st_size
        if solution_size > MAXIMUM_PROOF_UPLOAD_BYTES:
            raise RuntimeError("UNSAT proof files must be 100 MiB or smaller.")
        digest = _keccak_file_hex(solution_path)

    config = load_config()
    api = make_api(config)
    key = require_private_key(args)
    upload_id = str(uuid.uuid4())
    upload_token = secrets.token_urlsafe(32)
    upload_token_hash = f"0x{hashlib.sha256(upload_token.encode('ascii')).hexdigest()}"
    auth_fields = {
        "chain_id": int(config["chain_id"]),
        "bounty_manager": str(config["bounty_manager"]),
        "file_name": solution_path.name,
        "size": solution_size,
        "digest": digest,
        "solution_kind": solution_kind,
        "proof_format": proof_format,
        "upload_id": upload_id,
        "token_hash": upload_token_hash,
    }
    reservation_auth = sign_solution_upload_message(key, action="reserve", **auth_fields)
    reservation = api.initialize_solution_upload(
        upload_id=upload_id,
        token=upload_token,
        wallet=reservation_auth["wallet"],
        timestamp=reservation_auth["timestamp"],
        signature=reservation_auth["signature"],
        file_name=solution_path.name,
        size=solution_size,
        digest=digest,
        solution_kind=solution_kind,
        proof_format=proof_format,
    )
    upload_id, token = api.upload_reserved_solution(
        solution_path,
        reservation,
        content=solution_payload if solution_kind == 1 else None,
    )
    result = None
    completion_error: Exception | None = None
    for attempt in range(10):
        completion_auth = sign_solution_upload_message(key, action="complete", **auth_fields)
        try:
            result = api.complete_solution_upload(
                upload_id=upload_id,
                token=token,
                wallet=completion_auth["wallet"],
                timestamp=completion_auth["timestamp"],
                signature=completion_auth["signature"],
            )
            break
        except Exception as error:
            completion_error = error
            message = str(error).lower()
            retryable = any(
                marker in message
                for marker in (
                    "timed out",
                    "connection",
                    "temporarily",
                    "retry",
                    "being finalized",
                    "capacity is busy",
                    "http 429",
                    "http 503",
                    "http 504",
                )
            )
            if not retryable or attempt == 9:
                raise
            time.sleep(min(30, 2 ** attempt))
    if result is None:
        raise RuntimeError("Direct upload completion did not return an artifact.") from completion_error
    result = _validated_solution_artifact(
        result,
        digest=digest,
        name=solution_path.name,
        size=solution_size,
        solution_kind=solution_kind,
        proof_format=proof_format,
    )
    if maybe_json(args, result):
        return
    print("Solution uploaded")
    print(f"Kind: {solution_kind_label(solution_kind)}")
    print(f"Proof format: {proof_format_label(proof_format)}")
    print(f"Artifact ID: {result['artifactId']}")
    print(f"Digest: {result['digest']}")
    print(f"Size: {result['size']} bytes")


def _keccak_file_hex(path: Path) -> str:
    digest = keccak.new(digest_bits=256)
    with path.open("rb") as payload:
        while chunk := payload.read(1024 * 1024):
            digest.update(chunk)
    return f"0x{digest.hexdigest()}"


def _artifact_id(value: Any) -> str:
    if not isinstance(value, str):
        raise RuntimeError("Solution artifact id is required.")
    artifact_id = value.strip()
    if (
        not artifact_id
        or len(artifact_id.encode("utf-8")) > MAXIMUM_ARTIFACT_ID_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in artifact_id)
    ):
        raise RuntimeError("Solution artifact id is invalid.")
    return artifact_id


def _validated_solution_artifact(
    result: Any,
    *,
    digest: str,
    name: str,
    size: int,
    solution_kind: int,
    proof_format: int,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise RuntimeError("Completed direct upload did not return a solution artifact.")
    artifact_id = _artifact_id(result.get("artifactId"))
    if (
        str(result.get("digest") or "").lower() != digest.lower()
        or result.get("size") != size
        or result.get("name") != name
        or result.get("solutionKind") != solution_kind
        or result.get("proofFormat") != proof_format
    ):
        raise RuntimeError("Completed direct upload does not match the selected solution file.")
    # Return only the public opaque binding. Upload URLs, object keys and storage
    # metadata are transport details and must never become CLI output.
    return {
        "artifactId": artifact_id,
        "digest": digest.lower(),
        "name": name,
        "size": size,
        "solutionKind": solution_kind,
        "solutionKindName": result.get("solutionKindName") or solution_kind_label(solution_kind),
        "proofFormat": proof_format,
        "proofFormatName": result.get("proofFormatName") or proof_format_label(proof_format),
    }


def _prepare_commit_payload(args: argparse.Namespace, config: dict[str, Any]) -> dict[str, Any]:
    key = private_key_from_args(getattr(args, "private_key", None))
    solver = args.solver or (Account.from_key(key).address if key else None)
    if not solver:
        raise RuntimeError("Solver address required. Pass --solver or --private-key.")
    solution_kind = normalize_solution_kind(args.kind)
    proof_format = normalize_proof_format(args.proof_format, solution_kind)
    payload = {
        "bounty": args.bounty,
        "solver": solver,
        "solutionKind": solution_kind,
        "proofFormat": proof_format,
        "artifactId": _artifact_id(args.artifact_id),
        "solutionDigest": args.solution_digest,
    }
    if args.salt:
        payload["salt"] = args.salt
    return payload


def _print_commit_preview(prepared: dict[str, Any], config: dict[str, Any]) -> None:
    token = token_by_address(config, prepared["bondToken"])
    print(f"Bounty: {prepared['bountyCode']} ({prepared['bountyId']})")
    print(f"Solver: {prepared['solver']}")
    print(f"Solution kind: {prepared.get('solutionKindCode')} / {prepared.get('proofFormatName')}")
    print(f"Artifact ID: {_artifact_id(prepared.get('artifactId'))}")
    print(f"Solution digest: {prepared['solutionDigest']}")
    print(f"Salt: {prepared['salt']}")
    print(f"Commit hash: {prepared['commitHash']}")
    print(f"Solver bond: {format_token_amount(prepared['solverBond'], int(token['decimals']), token['symbol'])}")
    print_prepared_transactions(prepared["transactions"])


def _prepared_reveal_bundle(prepared: dict[str, Any], expected_artifact_id: str) -> dict[str, Any]:
    reveal_bundle = prepared.get("revealBundle")
    if not isinstance(reveal_bundle, dict):
        raise RuntimeError("Prepared commit did not return a reveal bundle.")
    try:
        canonical = {
            "bountyId": str(prepared["bountyId"]),
            "artifactId": expected_artifact_id,
            "solutionKind": int(prepared["solutionKind"]),
            "proofFormat": int(prepared["proofFormat"]),
            "solutionDigest": str(prepared["solutionDigest"]).lower(),
            "salt": str(prepared["salt"]).lower(),
            "commitHash": str(prepared["commitHash"]).lower(),
        }
        matches = (
            str(reveal_bundle.get("bountyId")) == canonical["bountyId"]
            and _artifact_id(reveal_bundle.get("artifactId")) == canonical["artifactId"]
            and int(reveal_bundle.get("solutionKind", -1)) == canonical["solutionKind"]
            and int(reveal_bundle.get("proofFormat", -1)) == canonical["proofFormat"]
            and str(reveal_bundle.get("solutionDigest", "")).lower() == canonical["solutionDigest"]
            and str(reveal_bundle.get("salt", "")).lower() == canonical["salt"]
            and str(reveal_bundle.get("commitHash", "")).lower() == canonical["commitHash"]
            and reveal_bundle.get("submissionId") in (None, "")
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("Prepared commit reveal bundle is malformed.") from error
    if not matches:
        raise RuntimeError("Prepared commit reveal bundle does not match the verified commit descriptor.")
    # Persist only the fields independently bound to the verified commit. This
    # prevents an unexpected API-only field (for example submissionId) from
    # changing a later `reveal` command.
    return canonical


def _safe_path_component(value: Any, *, fallback: str) -> str:
    raw = str(value).strip()
    component = re.sub(r"[^A-Za-z0-9_-]+", "-", raw).strip("-_")
    if not component:
        component = fallback
    if len(component) > 96:
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        component = f"{component[:79]}-{digest}"
    return component


def _default_reveal_bundle_path(prepared: dict[str, Any]) -> Path:
    bounty_id = _safe_path_component(prepared.get("bountyId"), fallback="unknown")
    commit_hash = _safe_path_component(prepared.get("commitHash"), fallback="unknown")
    return DEFAULT_REVEAL_BUNDLE_DIRECTORY / f"bounty-{bounty_id}-commit-{commit_hash}.json"


def _atomic_write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as temporary_file:
            json.dump(payload, temporary_file, indent=2)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        if os.name != "nt":
            path.chmod(0o600)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _write_reveal_bundle(
    prepared: dict[str, Any], reveal_bundle: dict[str, Any], output: str | None
) -> Path:
    path = Path(output).expanduser() if output else _default_reveal_bundle_path(prepared)
    _atomic_write_private_json(path, reveal_bundle)
    return path


def _commit_solution_data(bounty_id: Any, commit_hash: Any) -> str:
    try:
        digest = bytes.fromhex(str(commit_hash)[2:])
    except (TypeError, ValueError) as error:
        raise RuntimeError("Prepared commit hash is not valid bytes32 calldata.") from error
    if not str(commit_hash).startswith("0x") or len(digest) != 32:
        raise RuntimeError("Prepared commit hash is not valid bytes32 calldata.")
    selector = Web3.keccak(text="commitSolution(uint256,bytes32)")[:4]
    encoded = Web3().codec.encode(["uint256", "bytes32"], [int(bounty_id), digest])
    return f"0x{(selector + encoded).hex()}"


def _assert_commit_transaction_shape(
    prepared: dict[str, Any], config: dict[str, Any], chain: ChainClient
) -> None:
    transactions = prepared.get("transactions", [])
    if not isinstance(transactions, list) or any(not isinstance(tx, dict) for tx in transactions):
        raise RuntimeError("Prepared commit transactions are malformed.")
    unexpected = [
        transaction
        for transaction in transactions
        if transaction.get("functionName") not in {"approve", "commitSolution"}
    ]
    if unexpected:
        raise RuntimeError("Prepared commit contains an unexpected transaction.")
    commit_transactions = [
        transaction
        for transaction in transactions
        if transaction.get("functionName") == "commitSolution"
    ]
    if len(commit_transactions) != 1:
        raise RuntimeError("Prepared commit must contain exactly one commitSolution transaction.")
    expected = [str(prepared.get("bountyId")), str(prepared.get("commitHash"))]
    actual = [str(value) for value in commit_transactions[0].get("args", [])]
    if actual != expected:
        raise RuntimeError("Prepared commitSolution arguments do not match the digest-only protocol.")
    commit_transaction = commit_transactions[0]
    expected_manager = str(config["bounty_manager"])
    expected_data = _commit_solution_data(prepared.get("bountyId"), prepared.get("commitHash"))
    try:
        commit_value = int(commit_transaction.get("value") or 0)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Prepared commitSolution value is malformed.") from error
    if (
        str(commit_transaction.get("to", "")).lower() != expected_manager.lower()
        or str(commit_transaction.get("data", "")).lower() != expected_data.lower()
        or commit_value != 0
    ):
        raise RuntimeError("Prepared commitSolution calldata is not bound to the configured manager and commit hash.")

    approval_transactions = [
        transaction for transaction in transactions if transaction.get("functionName") == "approve"
    ]
    if len(approval_transactions) > 1:
        raise RuntimeError("Prepared commit contains more than one approval transaction.")
    if approval_transactions:
        approval = approval_transactions[0]
        bond_token = str(prepared.get("bondToken", ""))
        solver_bond = int(prepared.get("solverBond", 0))
        expected_approval_data = chain.approval_data(bond_token, expected_manager, solver_bond)
        expected_approval_args = [expected_manager, str(solver_bond)]
        actual_approval_args = [str(value) for value in approval.get("args", [])]
        try:
            approval_value = int(approval.get("value") or 0)
        except (TypeError, ValueError) as error:
            raise RuntimeError("Prepared approval value is malformed.") from error
        if (
            str(approval.get("to", "")).lower() != bond_token.lower()
            or str(approval.get("data", "")).lower() != expected_approval_data.lower()
            or actual_approval_args != expected_approval_args
            or approval_value != 0
        ):
            raise RuntimeError("Prepared approval is not bound to the bond token, manager, and amount.")


def _assert_commit_binding(
    prepared: dict[str, Any], payload: dict[str, Any], config: dict[str, Any]
) -> None:
    try:
        expected_fields = (
            int(prepared.get("chainId", -1)) == int(config["chain_id"])
            and str(prepared.get("bountyManager", "")).lower()
            == str(config["bounty_manager"]).lower()
            and str(prepared.get("solver", "")).lower() == str(payload.get("solver", "")).lower()
            and str(prepared.get("solutionDigest", "")).lower()
            == str(payload.get("solutionDigest", "")).lower()
            and int(prepared.get("solutionKind", -1)) == int(payload.get("solutionKind", -2))
            and int(prepared.get("proofFormat", -1)) == int(payload.get("proofFormat", -2))
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("Prepared commit descriptor is malformed.") from error
    if not expected_fields:
        raise RuntimeError("Prepared commit descriptor does not match the requested solution artifact.")
    expected_hash = compute_solution_commit_hash(
        chain_id=int(config["chain_id"]),
        bounty_manager=str(config["bounty_manager"]),
        bounty_id=str(prepared.get("bountyId")),
        solver=str(payload["solver"]),
        solution_kind=int(payload["solutionKind"]),
        proof_format=int(payload["proofFormat"]),
        solution_digest=str(payload["solutionDigest"]),
        salt=str(prepared.get("salt")),
    )
    if expected_hash.lower() != str(prepared.get("commitHash", "")).lower():
        raise RuntimeError("Prepared commit hash does not match the domain-separated digest-only protocol.")


def _assert_reveal_transaction_shape(prepared: dict[str, Any], payload: dict[str, Any]) -> None:
    reveal_transactions = [
        transaction
        for transaction in prepared.get("transactions", [])
        if isinstance(transaction, dict) and transaction.get("functionName") == "revealSolution"
    ]
    if len(reveal_transactions) != 1:
        raise RuntimeError("Prepared reveal must contain exactly one revealSolution transaction.")
    expected = [
        str(prepared.get("bountyId")),
        str(prepared.get("submissionId")),
        str(payload.get("solutionKind")),
        str(payload.get("proofFormat")),
        str(payload.get("solutionDigest")),
        str(payload.get("salt")),
    ]
    actual = [str(value) for value in reveal_transactions[0].get("args", [])]
    if actual != expected:
        raise RuntimeError("Prepared revealSolution arguments do not match the digest-only protocol.")


def _synchronize_commit_bond(prepared: dict[str, Any], config: dict[str, Any]) -> ChainClient:
    chain = make_chain(config)
    bounty_manager = str(prepared.get("bountyManager") or config["bounty_manager"])
    bounty_id = prepared["bountyId"]
    bond_token = str(prepared["bondToken"])
    solver_bond_source = "bounty-snapshot"
    try:
        solver_bond = chain.bounty_solver_bond(bounty_manager, bounty_id)
    except Exception as snapshot_error:
        legacy_fallback_allowed = (
            chain.chain_id == LEGACY_SOLVER_BOND_CHAIN_ID
            and bounty_manager.lower() == LEGACY_SOLVER_BOND_BOUNTY_MANAGER
        )
        if not legacy_fallback_allowed:
            raise RuntimeError("Could not read the bounty's snapshotted solver bond.") from snapshot_error

        api_bond_source = prepared.get("solverBondSource")
        if api_bond_source not in {None, "legacy-token-config"}:
            raise RuntimeError(
                "The API solver bond source does not match the configured legacy Arbitrum Sepolia manager."
            ) from snapshot_error

        # This exact Arbitrum Sepolia deployment predates per-bounty snapshots.
        # Its token-level value remains the authoritative on-chain source until
        # the audited BountyManager is deployed; no other manager may use it.
        solver_bond = chain.solver_bond_for_token(bounty_manager, bond_token)
        solver_bond_source = "legacy-token-config"

    if solver_bond <= 0:
        if solver_bond_source == "bounty-snapshot":
            raise RuntimeError("The bounty does not have a valid snapshotted solver bond.")
        raise RuntimeError("The legacy token configuration does not have a valid solver bond.")

    prepared["solverBond"] = str(solver_bond)
    prepared["solverBondSource"] = solver_bond_source
    for transaction in prepared.get("transactions", []):
        if transaction.get("functionName") != "approve":
            continue
        transaction["to"] = bond_token
        transaction["args"] = [bounty_manager, str(solver_bond)]
        transaction["data"] = chain.approval_data(bond_token, bounty_manager, solver_bond)
        transaction["value"] = "0"
    return chain


def command_prepare_commit(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    payload = _prepare_commit_payload(args, config)
    prepared = api.prepare_commit(payload)
    if _artifact_id(prepared.get("artifactId")) != payload["artifactId"]:
        raise RuntimeError("Prepared commit returned a different solution artifact id.")
    reveal_bundle = _prepared_reveal_bundle(prepared, payload["artifactId"])
    _assert_commit_binding(prepared, payload, config)
    chain = _synchronize_commit_bond(prepared, config)
    _assert_commit_transaction_shape(prepared, config, chain)
    if args.output:
        _write_reveal_bundle(prepared, reveal_bundle, args.output)
    if maybe_json(args, prepared):
        return
    _print_commit_preview(prepared, config)
    if args.output:
        print(f"Reveal bundle written: {args.output}")


def command_commit(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    payload = _prepare_commit_payload(args, config)
    prepared = api.prepare_commit(payload)
    if _artifact_id(prepared.get("artifactId")) != payload["artifactId"]:
        raise RuntimeError("Prepared commit returned a different solution artifact id.")
    reveal_bundle = _prepared_reveal_bundle(prepared, payload["artifactId"])
    _assert_commit_binding(prepared, payload, config)
    chain = _synchronize_commit_bond(prepared, config)
    _assert_commit_transaction_shape(prepared, config, chain)
    will_broadcast = bool(args.send and not args.json)
    key = require_private_key(args) if will_broadcast else None
    reveal_bundle_path = None
    if args.output or will_broadcast:
        # The salt must be recoverable before the first approval/commit transaction
        # can reach the chain. A failed write deliberately aborts the command.
        reveal_bundle_path = _write_reveal_bundle(prepared, reveal_bundle, args.output)
    if maybe_json(args, prepared):
        return
    _print_commit_preview(prepared, config)
    if reveal_bundle_path:
        print(f"Reveal bundle written: {reveal_bundle_path}")
    if not args.send:
        print("\nNot broadcast. Add --send to approve the solver bond and commit.")
        return
    if key is None:
        raise RuntimeError("Private key required before broadcasting the commit.")
    for tx in prepared["transactions"]:
        print(f"Sending {tx['label']}...")
        receipt = chain.send_prepared_transaction(tx, key)
        print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
        if receipt["status"] != 1:
            raise RuntimeError(f"{tx['label']} reverted.")
    print("Commit submitted. Keep the reveal bundle; it contains the salt required for reveal.")


def _load_reveal_bundle(args: argparse.Namespace) -> dict[str, Any]:
    if args.bundle:
        data = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError("Reveal bundle must be a JSON object.")
        if not (data.get("submissionId") or args.submission_id):
            raise RuntimeError("Reveal requires --submission-id because commit bundles do not know the on-chain submission id.")
        return data
    required = ["bounty", "submission_id", "artifact_id", "solution_digest", "salt"]
    missing = [name for name in required if not getattr(args, name)]
    if missing:
        raise RuntimeError(f"Missing reveal fields: {', '.join(missing)}. Use --bundle or provide explicit fields.")
    solution_kind = normalize_solution_kind(args.kind)
    proof_format = normalize_proof_format(args.proof_format, solution_kind)
    return {
        "bountyId": args.bounty,
        "submissionId": args.submission_id,
        "solutionKind": solution_kind,
        "proofFormat": proof_format,
        "artifactId": _artifact_id(args.artifact_id),
        "solutionDigest": args.solution_digest,
        "salt": args.salt,
    }


def command_reveal(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    bundle = _load_reveal_bundle(args)
    bounty_input = str(bundle.get("bountyId") or bundle.get("bounty") or args.bounty or "").strip()
    if not bounty_input:
        raise RuntimeError("Reveal requires a bounty id/code.")
    artifact_id = _artifact_id(bundle.get("artifactId") or args.artifact_id)
    payload = {
        "bounty": bounty_input,
        "submissionId": str(bundle.get("submissionId") or args.submission_id),
        "solutionKind": bundle.get("solutionKind", normalize_solution_kind(args.kind)),
        "proofFormat": bundle.get("proofFormat", normalize_proof_format(args.proof_format, normalize_solution_kind(args.kind))),
        "artifactId": artifact_id,
        "solutionDigest": bundle.get("solutionDigest"),
        "salt": bundle.get("salt"),
    }
    prepared = api.prepare_reveal(payload)
    _assert_reveal_transaction_shape(prepared, payload)
    if maybe_json(args, prepared):
        return
    print(f"Bounty: {prepared['bountyCode']} ({prepared['bountyId']})")
    print(f"Submission: {prepared['submissionId']}")
    print(f"Solution kind: {prepared.get('solutionKindCode')} / {prepared.get('proofFormatName')}")
    print_prepared_transactions(prepared["transactions"])
    if not args.send:
        print("\nNot broadcast. Add --send to reveal the solution.")
        return
    key = require_private_key(args)
    chain = make_chain(config)
    for tx in prepared["transactions"]:
        print(f"Sending {tx['label']}...")
        receipt = chain.send_prepared_transaction(tx, key)
        print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
        if receipt["status"] != 1:
            raise RuntimeError(f"{tx['label']} reverted.")
    print("Reveal submitted.")


def _resolve_bounty_and_token(api: ProtocolApi, config: dict[str, Any], bounty_input: str) -> tuple[dict[str, Any], dict[str, Any]]:
    result = api.bounty(bounty_input)
    token = token_by_address(config, result["bounty"]["paymentToken"])
    return result, token


def _read_matched_query(cnf_path: str | None) -> tuple[str, bytes] | None:
    if not cnf_path:
        return None
    path = Path(cnf_path)
    if not path.is_file():
        raise RuntimeError(f"CNF file not found: {path}")
    if not path.name.lower().endswith(".cnf"):
        raise RuntimeError("Matched answer queries must use a .cnf file.")
    try:
        payload, _parsed = load_dimacs_cnf_file(
            path,
            {"max_input_bytes": MAXIMUM_MATCHED_CNF_BYTES},
        )
    except InvalidDimacsError as error:
        if "byte resource limit" in str(error):
            raise RuntimeError("Matched answer CNF must be 25 MiB or smaller.") from error
        if path.stat().st_size == 0:
            raise RuntimeError("Matched answer CNF must not be empty.") from error
        raise
    return path.name, payload


def _finalized_winner_solution_kind(bounty_result: dict[str, Any]) -> int | None:
    bounty = bounty_result.get("bounty")
    if not isinstance(bounty, dict):
        return None
    winning_id = str(bounty.get("finalizedWinningSubmissionId") or "")
    if not winning_id or winning_id == "0":
        return None
    for submission in bounty_result.get("submissions") or []:
        if isinstance(submission, dict) and str(submission.get("submissionId") or "") == winning_id:
            try:
                return int(submission.get("solutionKind"))
            except (TypeError, ValueError):
                return None
    return None


def _keccak_hex(payload: bytes) -> str:
    digest = Web3.keccak(payload).hex()
    return digest if digest.startswith("0x") else f"0x{digest}"


def command_buy_answer(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    query_file = _read_matched_query(args.cnf)
    bounty_result, token = _resolve_bounty_and_token(api, config, args.bounty)
    key = require_private_key(args)
    chain = make_chain(config)
    account = Account.from_key(key)
    bounty_id = bounty_result["bountyId"]
    bounty = bounty_result["bounty"]
    controller = config["artifact_access_controller"]
    payment_token = bounty["paymentToken"]

    issuer_access = account.address.lower() == bounty["issuer"].lower()
    has_access = issuer_access or chain.can_access(controller, account.address, bounty_id)

    is_legacy_access_controller = (
        chain.chain_id == LEGACY_ACCESS_CONTROLLER_CHAIN_ID
        and controller.lower() == LEGACY_ARTIFACT_ACCESS_CONTROLLER
    )
    if is_legacy_access_controller:
        print(f"Bounty: {bounty_result['bountyCode']} ({bounty_id})")
        print(f"Wallet: {account.address}")
        if issuer_access:
            print("Issuer access detected. No purchase required.")
        elif has_access:
            print("This wallet already has answer access. No purchase required.")
        else:
            raise RuntimeError(
                "Paid answer purchases are disabled on the legacy Arbitrum Sepolia "
                "AccessController until the protected quote/epoch contract migration is complete."
            )
        if args.download:
            args.bounty = bounty_id
            command_download_answer(args, query_file=query_file)
        return

    quote_epoch, quote_status, price = chain.access_quote(controller, bounty_id, payment_token)
    _, solver, solver_amount, routed_amount = chain.access_distribution(controller, bounty_id, payment_token)

    print(f"Bounty: {bounty_result['bountyCode']} ({bounty_id})")
    print(f"Wallet: {account.address}")
    if quote_status == ACCESS_STATUS_PUBLIC:
        print("Access price: Public")
    elif quote_status == ACCESS_STATUS_DISABLED:
        print("Access price: Payment token disabled")
    elif quote_status == ACCESS_STATUS_UNCONFIGURED:
        print("Access price: Not configured")
    else:
        print(f"Access price: {format_token_amount(price, int(token['decimals']), token['symbol'])}")
    print(f"Solver share: {format_token_amount(solver_amount, int(token['decimals']), token['symbol'])} -> {short_address(solver)}")
    print(f"Routed amount: {format_token_amount(routed_amount, int(token['decimals']), token['symbol'])}")
    if issuer_access:
        print("Issuer access detected. No purchase required.")
    elif has_access:
        print("This wallet already has answer access. No purchase required.")
    else:
        if quote_status == ACCESS_STATUS_DISABLED:
            raise RuntimeError("Answer access purchases are disabled for this payment token.")
        if quote_status == ACCESS_STATUS_UNCONFIGURED:
            raise RuntimeError("Answer access pricing is not configured for this payment token.")
        if quote_status != ACCESS_STATUS_PRICED:
            raise RuntimeError(f"Unsupported answer access quote status: {quote_status}.")
        allowance = chain.allowance(payment_token, account.address, controller)
        balance = chain.token_balance(payment_token, account.address)
        print(f"Balance: {format_token_amount(balance, int(token['decimals']), token['symbol'])}")
        print(f"Allowance: {format_token_amount(allowance, int(token['decimals']), token['symbol'])}")
        if balance < price:
            raise RuntimeError("Insufficient token balance for answer access.")
        if not args.send:
            print("Not broadcast. Add --send to approve and purchase answer access.")
            return
        if allowance < price:
            print("Approving answer access fee...")
            receipt = chain.approve(payment_token, controller, price, key)
            print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
            if receipt["status"] != 1:
                raise RuntimeError("Approval reverted.")
        print("Purchasing answer access...")
        receipt = chain.purchase_access(controller, bounty_id, payment_token, price, quote_epoch, key)
        print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
        if receipt["status"] != 1:
            raise RuntimeError("Purchase reverted.")
    if args.download:
        args.bounty = bounty_id
        command_download_answer(args, query_file=query_file)


def command_download_answer(
    args: argparse.Namespace, *, query_file: tuple[str, bytes] | None = None
) -> None:
    if query_file is None:
        query_file = _read_matched_query(args.cnf)
    else:
        parse_dimacs_cnf_bytes(
            query_file[1],
            {"max_input_bytes": MAXIMUM_MATCHED_CNF_BYTES},
        )
    config = load_config()
    api = make_api(config)
    bounty_result = api.bounty(args.bounty)
    key = require_private_key(args)
    bounty_id = bounty_result["bountyId"]
    requested_matched_query = query_file is not None
    transform_timeout_minutes = int(getattr(args, "transform_timeout_minutes", 60))
    if transform_timeout_minutes < 1 or transform_timeout_minutes > 24 * 60:
        raise RuntimeError("--transform-timeout-minutes must be between 1 and 1440.")
    request_query_file = query_file
    query_upload: tuple[str, str] | None = None

    if query_file is not None:
        query_digest = _keccak_hex(query_file[1]).lower()
        source_digest = str(bounty_result.get("bounty", {}).get("instanceDigest") or "").lower()
        if source_digest and query_digest == source_digest:
            # A raw-exact query can use the byte-preserving GET route without
            # posting the CNF through the web function again.
            request_query_file = None
        elif len(query_file[1]) > DIRECT_MATCHED_CNF_UPLOAD_THRESHOLD_BYTES:
            initial_auth = sign_access_message(
                key,
                chain_id=int(config["chain_id"]),
                bounty_manager=config["bounty_manager"],
                bounty_id=bounty_id,
            )
            query_upload = api.upload_unsat_transform_target(
                bounty_id=bounty_id,
                wallet=initial_auth["wallet"],
                timestamp=initial_auth["timestamp"],
                signature=initial_auth["signature"],
                query_file=query_file,
            )
            request_query_file = None

    auth = sign_access_message(
        key,
        chain_id=int(config["chain_id"]),
        bounty_manager=config["bounty_manager"],
        bounty_id=bounty_id,
    )
    payload, disposition = api.download_answer(
        bounty_id=bounty_id,
        wallet=auth["wallet"],
        timestamp=auth["timestamp"],
        signature=auth["signature"],
        query_file=request_query_file,
        query_upload=query_upload,
        max_wait_seconds=transform_timeout_minutes * 60,
    )
    fallback = f"3sat_{bounty_result['bountyCode']}{'_matched' if requested_matched_query else ''}.zip"
    output = Path(args.output or filename_from_content_disposition(disposition, fallback))
    write_bytes(output, payload)
    print(f"Downloaded: {output}")
    if requested_matched_query:
        print(
            "Matched answer bundle downloaded. SAT assignments and UNSAT proofs are delivered "
            "for the provided CNF; transformed UNSAT proofs are returned only after the target "
            "proof checker accepts them."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="3sat", description="Command line client for the 3SAT protocol.")
    parser.add_argument("--version", action="version", version="3sat 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    config = sub.add_parser("config", help="Manage non-sensitive CLI configuration.")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    init = config_sub.add_parser("init", help="Create ~/.3sat/config.json with default values.")
    init.add_argument("--force", action="store_true", help="Overwrite existing config.")
    config_sub.add_parser("show", help="Show merged configuration.")
    set_cmd = config_sub.add_parser("set", help="Set one config key.")
    set_cmd.add_argument("key")
    set_cmd.add_argument("value")
    config.set_defaults(func=command_config)

    standardize = sub.add_parser("standardize", help="Normalize a DIMACS CNF file through the 3SAT API.")
    standardize.add_argument("cnf")
    standardize.add_argument("-o", "--output")
    standardize.add_argument("--print-text", action="store_true")
    standardize.add_argument("--json", action="store_true")
    standardize.set_defaults(func=command_standardize)

    search = sub.add_parser("search", help="Search the answer database for a DIMACS CNF file.")
    search.add_argument("cnf")
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=command_search)

    marketplace = sub.add_parser("marketplace", help="List indexed bounties.")
    marketplace.add_argument("--sync", action="store_true", help="Ask the API to sync before returning.")
    marketplace.add_argument("--limit", type=int, default=20, help="Number of bounties to show. Default: 20.")
    marketplace.add_argument("--offset", type=int, default=0, help="Pagination offset for loading the next page.")
    marketplace.add_argument("--json", action="store_true")
    marketplace.set_defaults(func=command_marketplace)

    bounty = sub.add_parser("bounty", help="Load a bounty by public code or internal id.")
    bounty.add_argument("bounty")
    bounty.add_argument("--json", action="store_true")
    bounty.set_defaults(func=command_bounty)

    balance = sub.add_parser("balance", help="Show native, USDC, and $3SAT balances.")
    balance.add_argument("--address")
    balance.add_argument("--private-key")
    balance.add_argument("--json", action="store_true")
    balance.set_defaults(func=command_balance)

    tokens = sub.add_parser("tokens", help="Show supported payment token addresses and decimals.")
    tokens.add_argument("--onchain", action="store_true", help="Read symbol/decimals/code from chain.")
    tokens.add_argument("--json", action="store_true")
    tokens.set_defaults(func=command_tokens)

    doctor = sub.add_parser("doctor", help="Check API, RPC, contracts, tokens, and optional wallet balances.")
    doctor.add_argument("--address")
    doctor.add_argument("--private-key")
    doctor.set_defaults(func=command_doctor)

    issue = sub.add_parser("issue", help="Upload a CNF instance and create a bounty.")
    issue.add_argument("cnf")
    issue.add_argument("--reward", required=True, help="Human token amount, e.g. 100 or 0.5.")
    issue.add_argument("--token", default="USDC", choices=["USDC", "3SAT"], help="Bounty payment asset.")
    issue.add_argument("--title", default="SAT Bounty")
    issue.add_argument("--description", default="", help="Public task description. Maximum 200 characters.")
    issue.add_argument("--posting-fee", default="0")
    issue.add_argument("--open-hours", type=float, default=MINIMUM_BOUNTY_WINDOW_HOURS)
    issue.add_argument("--reveal-hours", type=float, default=MINIMUM_BOUNTY_WINDOW_HOURS)
    issue.add_argument("--verify-hours", type=float, default=MINIMUM_BOUNTY_WINDOW_HOURS)
    issue.add_argument(
        "--quorum",
        type=int,
        choices=[REQUIRED_VERIFIER_QUORUM],
        default=REQUIRED_VERIFIER_QUORUM,
        help=f"Verifier quorum; temporarily fixed at {REQUIRED_VERIFIER_QUORUM}.",
    )
    issue.add_argument("--dry-run", action="store_true", help="Only validate local CNF/params and print preview; upload nothing.")
    issue.add_argument("--send", action="store_true", help="Broadcast the approve and create-bounty transactions.")
    issue.add_argument("--private-key")
    issue.add_argument("--json", action="store_true", help="Print prepared transaction JSON and do not broadcast.")
    issue.set_defaults(func=command_issue)

    upload_solution = sub.add_parser("upload-solution", help="Upload a SAT assignment or UNSAT proof artifact.")
    upload_solution.add_argument("solution")
    upload_solution.add_argument("--kind", default="sat", choices=["sat", "unsat", "SAT", "UNSAT"])
    upload_solution.add_argument("--proof-format", default="drat", choices=["drat", "frat", "lrat", "DRAT", "FRAT", "LRAT"])
    upload_solution.add_argument(
        "--private-key",
        help="Required for wallet-authenticated solution uploads; may also be set with 3SAT_PRIVATE_KEY.",
    )
    upload_solution.add_argument("--json", action="store_true")
    upload_solution.set_defaults(func=command_upload_solution)

    def add_commit_args(commit_parser: argparse.ArgumentParser) -> None:
        commit_parser.add_argument("bounty")
        commit_parser.add_argument("--solver", help="Solver wallet address. Optional if --private-key is provided.")
        commit_parser.add_argument("--artifact-id", required=True, help="Opaque artifact id returned by upload-solution.")
        commit_parser.add_argument("--solution-digest", required=True)
        commit_parser.add_argument("--kind", default="sat", choices=["sat", "unsat", "SAT", "UNSAT"])
        commit_parser.add_argument("--proof-format", default="drat", choices=["drat", "frat", "lrat", "DRAT", "FRAT", "LRAT"])
        commit_parser.add_argument("--salt", help="Optional bytes32 salt. Generated by the API if omitted.")
        commit_parser.add_argument("--private-key")
        commit_parser.add_argument("-o", "--output", help="Write reveal bundle JSON.")
        commit_parser.add_argument("--json", action="store_true")

    prepare_commit = sub.add_parser("prepare-commit", help="Prepare solver bond approval and commit transaction data.")
    add_commit_args(prepare_commit)
    prepare_commit.set_defaults(func=command_prepare_commit)

    commit = sub.add_parser("commit", help="Prepare and optionally broadcast solver bond approval plus commit.")
    add_commit_args(commit)
    commit.add_argument("--send", action="store_true", help="Broadcast approval and commit transactions.")
    commit.set_defaults(func=command_commit)

    reveal = sub.add_parser("reveal", help="Prepare and optionally broadcast a reveal transaction.")
    reveal.add_argument("--bundle", help="Reveal bundle JSON from prepare-commit/commit.")
    reveal.add_argument("--bounty", help="Bounty code or id; optional if bundle includes bountyId.")
    reveal.add_argument("--submission-id", help="Submission id assigned by the commit transaction.")
    reveal.add_argument("--artifact-id", help="Opaque artifact id returned by upload-solution.")
    reveal.add_argument("--solution-digest")
    reveal.add_argument("--salt")
    reveal.add_argument("--kind", default="sat", choices=["sat", "unsat", "SAT", "UNSAT"])
    reveal.add_argument("--proof-format", default="drat", choices=["drat", "frat", "lrat", "DRAT", "FRAT", "LRAT"])
    reveal.add_argument("--send", action="store_true", help="Broadcast reveal transaction.")
    reveal.add_argument("--private-key")
    reveal.add_argument("--json", action="store_true")
    reveal.set_defaults(func=command_reveal)

    buy = sub.add_parser("buy-answer", help="Approve and pay for answer access.")
    buy.add_argument("bounty")
    buy.add_argument("--send", action="store_true", help="Broadcast approval and purchase transactions.")
    buy.add_argument("--download", action="store_true", help="Download after purchase/access check.")
    buy.add_argument(
        "--cnf",
        help=(
            "CNF query file. Equivalent SAT assignments may be rebuilt, and UNSAT proofs are "
            "converted and checked against this exact CNF before download."
        ),
    )
    buy.add_argument("-o", "--output")
    buy.add_argument(
        "--transform-timeout-minutes",
        type=int,
        default=60,
        help="Maximum time to wait for checked UNSAT proof conversion when --download is used (default: 60).",
    )
    buy.add_argument("--private-key")
    buy.set_defaults(func=command_buy_answer)

    download = sub.add_parser("download-answer", help="Download an answer bundle after issuer or paid-access checks.")
    download.add_argument("bounty")
    download.add_argument(
        "--cnf",
        help=(
            "CNF query file. Equivalent SAT assignments may be rebuilt, and UNSAT proofs are "
            "converted and checked against this exact CNF before download."
        ),
    )
    download.add_argument("-o", "--output")
    download.add_argument(
        "--transform-timeout-minutes",
        type=int,
        default=60,
        help="Maximum time to wait for checked UNSAT proof conversion (default: 60).",
    )
    download.add_argument("--private-key")
    download.set_defaults(func=command_download_answer)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
