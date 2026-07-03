from __future__ import annotations

import time
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3


SOLUTION_ARTIFACT_TYPE = 2


ERC20_ABI = [
    {
        "type": "function",
        "name": "approve",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "allowance",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "balanceOf",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "decimals",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
    {
        "type": "function",
        "name": "symbol",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "string"}],
    },
]


ARTIFACT_ACCESS_ABI = [
    {
        "type": "function",
        "name": "accessDistribution",
        "stateMutability": "view",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "artifactType", "type": "uint8"},
            {"name": "paymentToken", "type": "address"},
        ],
        "outputs": [
            {"name": "price", "type": "uint256"},
            {"name": "solver", "type": "address"},
            {"name": "solverAmount", "type": "uint256"},
            {"name": "routedAmount", "type": "uint256"},
        ],
    },
    {
        "type": "function",
        "name": "canAccess",
        "stateMutability": "view",
        "inputs": [
            {"name": "user", "type": "address"},
            {"name": "bountyId", "type": "uint256"},
            {"name": "artifactType", "type": "uint8"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "purchaseAccess",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "artifactType", "type": "uint8"},
            {"name": "paymentToken", "type": "address"},
        ],
        "outputs": [],
    },
]


class ChainClient:
    def __init__(self, rpc_url: str, expected_chain_id: int | None = None) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
        if not self.w3.is_connected():
            raise RuntimeError(f"Could not connect to RPC: {rpc_url}")
        self.chain_id = int(self.w3.eth.chain_id)
        if expected_chain_id is not None and self.chain_id != int(expected_chain_id):
            raise RuntimeError(f"Connected chain id {self.chain_id}, expected {expected_chain_id}.")

    @staticmethod
    def account(private_key: str):
        return Account.from_key(private_key)

    def token_contract(self, address: str):
        return self.w3.eth.contract(address=self.w3.to_checksum_address(address), abi=ERC20_ABI)

    def artifact_access_contract(self, address: str):
        return self.w3.eth.contract(address=self.w3.to_checksum_address(address), abi=ARTIFACT_ACCESS_ABI)

    def token_info(self, address: str) -> dict[str, Any]:
        contract = self.token_contract(address)
        try:
            symbol = contract.functions.symbol().call()
        except Exception:
            symbol = address
        try:
            decimals = int(contract.functions.decimals().call())
        except Exception:
            decimals = 18
        return {"address": address, "symbol": symbol, "decimals": decimals}

    def token_balance(self, token: str, address: str) -> int:
        return int(self.token_contract(token).functions.balanceOf(self.w3.to_checksum_address(address)).call())

    def native_balance(self, address: str) -> int:
        return int(self.w3.eth.get_balance(self.w3.to_checksum_address(address)))

    def allowance(self, token: str, owner: str, spender: str) -> int:
        contract = self.token_contract(token)
        return int(
            contract.functions.allowance(
                self.w3.to_checksum_address(owner),
                self.w3.to_checksum_address(spender),
            ).call()
        )

    def can_access(self, controller: str, wallet: str, bounty_id: str | int) -> bool:
        contract = self.artifact_access_contract(controller)
        return bool(
            contract.functions.canAccess(
                self.w3.to_checksum_address(wallet),
                int(bounty_id),
                SOLUTION_ARTIFACT_TYPE,
            ).call()
        )

    def access_distribution(self, controller: str, bounty_id: str | int, payment_token: str) -> tuple[int, str, int, int]:
        contract = self.artifact_access_contract(controller)
        price, solver, solver_amount, routed_amount = contract.functions.accessDistribution(
            int(bounty_id),
            SOLUTION_ARTIFACT_TYPE,
            self.w3.to_checksum_address(payment_token),
        ).call()
        return int(price), solver, int(solver_amount), int(routed_amount)

    def send_prepared_transaction(self, tx: dict[str, Any], private_key: str) -> dict[str, Any]:
        return self.send_transaction(
            to=tx["to"],
            data=tx["data"],
            value=int(tx.get("value") or 0),
            private_key=private_key,
            label=tx.get("label", tx.get("functionName", "transaction")),
        )

    def approve(self, token: str, spender: str, amount: int, private_key: str) -> dict[str, Any]:
        contract = self.token_contract(token)
        account = self.account(private_key)
        fn = contract.functions.approve(self.w3.to_checksum_address(spender), int(amount))
        tx = fn.build_transaction({"from": account.address, "value": 0})
        return self.send_built_transaction(tx, private_key, "approve")

    def purchase_access(self, controller: str, bounty_id: str | int, payment_token: str, private_key: str) -> dict[str, Any]:
        contract = self.artifact_access_contract(controller)
        account = self.account(private_key)
        fn = contract.functions.purchaseAccess(
            int(bounty_id),
            SOLUTION_ARTIFACT_TYPE,
            self.w3.to_checksum_address(payment_token),
        )
        tx = fn.build_transaction({"from": account.address, "value": 0})
        return self.send_built_transaction(tx, private_key, "purchaseAccess")

    def send_transaction(self, *, to: str, data: str, value: int, private_key: str, label: str) -> dict[str, Any]:
        account = self.account(private_key)
        tx = {
            "from": account.address,
            "to": self.w3.to_checksum_address(to),
            "value": int(value),
            "data": data,
        }
        return self.send_built_transaction(tx, private_key, label)

    def send_built_transaction(self, tx: dict[str, Any], private_key: str, label: str) -> dict[str, Any]:
        account = self.account(private_key)
        tx = dict(tx)
        tx["from"] = account.address
        tx["nonce"] = self.w3.eth.get_transaction_count(account.address, "pending")
        tx["chainId"] = self.chain_id
        tx.setdefault("value", 0)

        if "gas" not in tx:
            estimated = self.w3.eth.estimate_gas(tx)
            tx["gas"] = int(estimated * 1.2)

        tx.pop("gasPrice", None)
        latest = self.w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")
        if base_fee is not None:
            try:
                priority_fee = int(self.w3.eth.max_priority_fee)
            except Exception:
                priority_fee = self.w3.to_wei(0.01, "gwei")
            tx["maxPriorityFeePerGas"] = priority_fee
            tx["maxFeePerGas"] = int(base_fee) * 2 + priority_fee
        else:
            tx["gasPrice"] = int(self.w3.eth.gas_price)

        signed = Account.sign_transaction(tx, private_key)
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        tx_hash = self.w3.eth.send_raw_transaction(raw)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        return {
            "label": label,
            "hash": tx_hash.hex(),
            "status": int(receipt.status),
            "gasUsed": int(receipt.gasUsed),
        }


def artifact_access_auth_message(
    *,
    action: str,
    wallet: str,
    bounty_id: str,
    timestamp: str,
    chain_id: int,
    bounty_manager: str,
) -> str:
    return "\n".join(
        [
            "3SAT Artifact Access",
            f"action: {action}",
            f"chainId: {chain_id}",
            f"bountyManager: {bounty_manager}",
            f"wallet: {wallet.lower()}",
            f"bountyId: {bounty_id}",
            f"timestamp: {timestamp}",
        ]
    )


def sign_access_message(private_key: str, *, chain_id: int, bounty_manager: str, bounty_id: str, action: str = "answer-bundle") -> dict[str, str]:
    account = Account.from_key(private_key)
    timestamp = str(int(time.time() * 1000))
    message = artifact_access_auth_message(
        action=action,
        wallet=account.address,
        bounty_id=str(bounty_id),
        timestamp=timestamp,
        chain_id=chain_id,
        bounty_manager=bounty_manager,
    )
    signed = Account.sign_message(encode_defunct(text=message), private_key)
    return {"wallet": account.address, "timestamp": timestamp, "signature": signed.signature.hex(), "message": message}

