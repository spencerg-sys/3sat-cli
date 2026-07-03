from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from eth_account import Account

from .api import ProtocolApi
from .chain import ChainClient, SOLUTION_ARTIFACT_TYPE, sign_access_message
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
from .formatting import (
    filename_from_content_disposition,
    format_token_amount,
    normalize_proof_format,
    normalize_solution_kind,
    parse_token_amount,
    print_json,
    proof_format_label,
    read_text_file,
    short_address,
    solution_kind_label,
    validate_dimacs_cnf,
    write_bytes,
)


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
    api = make_api(load_config())
    text = read_text_file(args.cnf)
    result = api.standardize(text)
    if maybe_json(args, result):
        return
    print("CNF standardized")
    print(f"Variables: {result.get('variables')}")
    print(f"Clauses:   {result.get('clauses')}")
    print(f"Digest:    {result.get('canonicalDigest')}")
    if args.output:
        Path(args.output).write_text(result["canonicalText"], encoding="utf-8")
        print(f"Wrote:     {args.output}")
    elif args.print_text:
        print("\n" + result["canonicalText"])


def command_search(args: argparse.Namespace) -> None:
    api = make_api(load_config())
    text = read_text_file(args.cnf)
    result = api.search(text)
    if maybe_json(args, result):
        return
    query = result.get("query", {})
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
    result = api.marketplace(sync=args.sync)
    if maybe_json(args, result):
        return
    status = result.get("status", {})
    bounties = result.get("bounties") or []
    print(f"Marketplace: {len(bounties)} bounties")
    print(f"Indexer storage: {status.get('storage')} / last block {status.get('lastIndexedBlock')}")
    for bounty in bounties[: args.limit]:
        reward = bounty.get("reward", "-")
        code = bounty.get("bountyCode") or bounty.get("bountyId")
        state = bounty.get("status") or bounty.get("statusLabel") or ("finalized" if bounty.get("finalized") else "open")
        print(f"- {code}: reward {reward}, {state}")


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
        print_check("Marketplace API", True, f"{len(marketplace.get('bounties') or [])} cached bounties")
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
    config = load_config()
    api = make_api(config)
    token = token_by_symbol(config, args.token)
    instance_path = Path(args.cnf)
    if not instance_path.exists():
        raise RuntimeError(f"CNF file not found: {instance_path}")

    cnf_text = read_text_file(instance_path)
    cnf_summary = validate_dimacs_cnf(cnf_text)
    commit_seconds = int(round(float(args.open_hours) * 3600))
    reveal_seconds = int(round(float(args.reveal_hours) * 3600))
    verify_seconds = int(round(float(args.verify_hours) * 3600))
    if commit_seconds <= 0 or reveal_seconds <= 0 or verify_seconds <= 0:
        raise RuntimeError("All timing windows must be greater than zero.")
    if args.quorum <= 0:
        raise RuntimeError("Verifier quorum must be greater than zero.")

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
    instance = api.upload_file("instance", instance_path, content_type="text/plain")
    print(f"Instance uploaded. Digest: {instance['digest']}")

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
    config = load_config()
    api = make_api(config)
    solution_path = Path(args.solution)
    if not solution_path.exists():
        raise RuntimeError(f"Solution file not found: {solution_path}")
    solution_kind = normalize_solution_kind(args.kind)
    proof_format = normalize_proof_format(args.proof_format, solution_kind)
    result = api.upload_file(
        "solution",
        solution_path,
        content_type="text/plain",
        solution_kind=solution_kind,
        proof_format=proof_format,
    )
    if maybe_json(args, result):
        return
    print("Solution uploaded")
    print(f"Kind: {solution_kind_label(solution_kind)}")
    print(f"Proof format: {proof_format_label(proof_format)}")
    print(f"Ref: {result['ref']}")
    print(f"Digest: {result['digest']}")
    print(f"Size: {result['size']} bytes")


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
        "solutionRef": args.solution_ref,
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
    print(f"Solution ref: {prepared['solutionRef']}")
    print(f"Solution digest: {prepared['solutionDigest']}")
    print(f"Salt: {prepared['salt']}")
    print(f"Commit hash: {prepared['commitHash']}")
    print(f"Solver bond: {format_token_amount(prepared['solverBond'], int(token['decimals']), token['symbol'])}")
    print_prepared_transactions(prepared["transactions"])


def command_prepare_commit(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    prepared = api.prepare_commit(_prepare_commit_payload(args, config))
    if args.output:
        Path(args.output).write_text(json.dumps(prepared["revealBundle"], indent=2) + "\n", encoding="utf-8")
    if maybe_json(args, prepared):
        return
    _print_commit_preview(prepared, config)
    if args.output:
        print(f"Reveal bundle written: {args.output}")


def command_commit(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    prepared = api.prepare_commit(_prepare_commit_payload(args, config))
    if args.output:
        Path(args.output).write_text(json.dumps(prepared["revealBundle"], indent=2) + "\n", encoding="utf-8")
    if maybe_json(args, prepared):
        return
    _print_commit_preview(prepared, config)
    if args.output:
        print(f"Reveal bundle written: {args.output}")
    if not args.send:
        print("\nNot broadcast. Add --send to approve the solver bond and commit.")
        return
    key = require_private_key(args)
    chain = make_chain(config)
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
    required = ["bounty", "submission_id", "solution_ref", "solution_digest", "salt"]
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
        "solutionRef": args.solution_ref,
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
    payload = {
        "bounty": bounty_input,
        "submissionId": str(bundle.get("submissionId") or args.submission_id),
        "solutionKind": bundle.get("solutionKind", normalize_solution_kind(args.kind)),
        "proofFormat": bundle.get("proofFormat", normalize_proof_format(args.proof_format, normalize_solution_kind(args.kind))),
        "solutionRef": bundle.get("solutionRef"),
        "solutionDigest": bundle.get("solutionDigest"),
        "salt": bundle.get("salt"),
    }
    prepared = api.prepare_reveal(payload)
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


def command_buy_answer(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    key = require_private_key(args)
    chain = make_chain(config)
    account = Account.from_key(key)
    bounty_result, token = _resolve_bounty_and_token(api, config, args.bounty)
    bounty_id = bounty_result["bountyId"]
    bounty = bounty_result["bounty"]
    controller = config["artifact_access_controller"]
    payment_token = bounty["paymentToken"]

    issuer_access = account.address.lower() == bounty["issuer"].lower()
    has_access = issuer_access or chain.can_access(controller, account.address, bounty_id)
    price, solver, solver_amount, routed_amount = chain.access_distribution(controller, bounty_id, payment_token)

    print(f"Bounty: {bounty_result['bountyCode']} ({bounty_id})")
    print(f"Wallet: {account.address}")
    print(f"Access price: {format_token_amount(price, int(token['decimals']), token['symbol'])}")
    print(f"Solver share: {format_token_amount(solver_amount, int(token['decimals']), token['symbol'])} -> {short_address(solver)}")
    print(f"Routed amount: {format_token_amount(routed_amount, int(token['decimals']), token['symbol'])}")
    if issuer_access:
        print("Issuer access detected. No purchase required.")
    elif has_access:
        print("This wallet already has answer access. No purchase required.")
    else:
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
        receipt = chain.purchase_access(controller, bounty_id, payment_token, key)
        print(f"  tx {receipt['hash']} status={receipt['status']} gas={receipt['gasUsed']}")
        if receipt["status"] != 1:
            raise RuntimeError("Purchase reverted.")
    if args.download:
        args.bounty = bounty_id
        command_download_answer(args)


def command_download_answer(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    key = require_private_key(args)
    bounty_result = api.bounty(args.bounty)
    bounty_id = bounty_result["bountyId"]
    auth = sign_access_message(
        key,
        chain_id=int(config["chain_id"]),
        bounty_manager=config["bounty_manager"],
        bounty_id=bounty_id,
    )
    query_text = read_text_file(args.cnf) if args.cnf else None
    payload, disposition = api.download_answer(
        bounty_id=bounty_id,
        wallet=auth["wallet"],
        timestamp=auth["timestamp"],
        signature=auth["signature"],
        query_text=query_text,
    )
    fallback = f"3sat_{bounty_result['bountyCode']}{'_matched' if query_text else ''}.zip"
    output = Path(args.output or filename_from_content_disposition(disposition, fallback))
    write_bytes(output, payload)
    print(f"Downloaded: {output}")
    if query_text:
        print("This matched bundle is rebuilt for the CNF you provided.")


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
    marketplace.add_argument("--limit", type=int, default=20)
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
    issue.add_argument("--description", default="")
    issue.add_argument("--posting-fee", default="0")
    issue.add_argument("--open-hours", type=float, default=24)
    issue.add_argument("--reveal-hours", type=float, default=2)
    issue.add_argument("--verify-hours", type=float, default=24)
    issue.add_argument("--quorum", type=int, default=1)
    issue.add_argument("--dry-run", action="store_true", help="Only validate local CNF/params and print preview; upload nothing.")
    issue.add_argument("--send", action="store_true", help="Broadcast the approve and create-bounty transactions.")
    issue.add_argument("--private-key")
    issue.add_argument("--json", action="store_true", help="Print prepared transaction JSON and do not broadcast.")
    issue.set_defaults(func=command_issue)

    upload_solution = sub.add_parser("upload-solution", help="Upload a SAT assignment or UNSAT proof artifact.")
    upload_solution.add_argument("solution")
    upload_solution.add_argument("--kind", default="sat", choices=["sat", "unsat", "SAT", "UNSAT"])
    upload_solution.add_argument("--proof-format", default="drat", choices=["drat", "frat", "lrat", "DRAT", "FRAT", "LRAT"])
    upload_solution.add_argument("--json", action="store_true")
    upload_solution.set_defaults(func=command_upload_solution)

    def add_commit_args(commit_parser: argparse.ArgumentParser) -> None:
        commit_parser.add_argument("bounty")
        commit_parser.add_argument("--solver", help="Solver wallet address. Optional if --private-key is provided.")
        commit_parser.add_argument("--solution-ref", required=True)
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
    reveal.add_argument("--solution-ref")
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
    buy.add_argument("--cnf", help="CNF query file; downloads a matched bundle rebuilt for this CNF.")
    buy.add_argument("-o", "--output")
    buy.add_argument("--private-key")
    buy.set_defaults(func=command_buy_answer)

    download = sub.add_parser("download-answer", help="Download an answer bundle after issuer or paid-access checks.")
    download.add_argument("bounty")
    download.add_argument("--cnf", help="CNF query file; downloads a matched bundle rebuilt for this CNF.")
    download.add_argument("-o", "--output")
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
