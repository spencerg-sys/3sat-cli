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
    print_json,
    read_text_file,
    short_address,
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


def command_issue(args: argparse.Namespace) -> None:
    config = load_config()
    api = make_api(config)
    token = token_by_symbol(config, args.token)
    instance_path = Path(args.cnf)
    if not instance_path.exists():
        raise RuntimeError(f"CNF file not found: {instance_path}")

    print(f"Uploading instance: {instance_path}")
    instance = api.upload_file("instance", instance_path, content_type="text/plain")
    print(f"Instance uploaded. Digest: {instance['digest']}")

    commit_seconds = int(round(float(args.open_hours) * 3600))
    reveal_seconds = int(round(float(args.reveal_hours) * 3600))
    verify_seconds = int(round(float(args.verify_hours) * 3600))

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
    print(f"Escrow amount: {prepared['escrowAmount']} raw units")
    print(f"Verifier reward pool: {prepared['verifierRewardPool']} raw units")
    for index, tx in enumerate(prepared["transactions"], start=1):
        print(f"{index}. {tx['label']} -> {tx['to']}")

    if not args.send:
        print("\nNot broadcast. Re-run with --send to submit transactions.")
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
    issue.add_argument("--send", action="store_true", help="Broadcast the approve and create-bounty transactions.")
    issue.add_argument("--private-key")
    issue.add_argument("--json", action="store_true", help="Print prepared transaction JSON and do not broadcast.")
    issue.set_defaults(func=command_issue)

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

