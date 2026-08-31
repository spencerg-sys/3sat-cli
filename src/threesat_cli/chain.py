from __future__ import annotations

import time
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3


SOLUTION_ARTIFACT_TYPE = 2
ACCESS_STATUS_UNCONFIGURED = 0
ACCESS_STATUS_PUBLIC = 1
ACCESS_STATUS_PRICED = 2
ACCESS_STATUS_DISABLED = 3
ACCESS_PURCHASE_DEADLINE_SECONDS = 30 * 60


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
        "name": "accessQuoteWithEpoch",
        "stateMutability": "view",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "artifactType", "type": "uint8"},
            {"name": "paymentToken", "type": "address"},
        ],
        "outputs": [
            {"name": "epoch", "type": "uint256"},
            {"name": "status", "type": "uint8"},
            {"name": "price", "type": "uint256"},
        ],
    },
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
            {"name": "maxPrice", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
            {"name": "expectedManagerEpoch", "type": "uint256"},
        ],
        "outputs": [],
    },
]


BOUNTY_MANAGER_ABI = [
    {
        "type": "function",
        "name": "createBounty",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "paymentToken", "type": "address"},
            {"name": "instanceCID", "type": "string"},
            {"name": "instanceDigest", "type": "bytes32"},
            {"name": "metadataURI", "type": "string"},
            {"name": "metadataDigest", "type": "bytes32"},
            {"name": "reward", "type": "uint256"},
            {"name": "postingFee", "type": "uint256"},
            {"name": "commitWindow", "type": "uint64"},
            {"name": "revealWindow", "type": "uint64"},
            {"name": "verificationWindow", "type": "uint64"},
            {"name": "verifierQuorum", "type": "uint16"},
        ],
        "outputs": [{"name": "bountyId", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "commitSolution",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "commitHash", "type": "bytes32"},
        ],
        "outputs": [{"name": "submissionId", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "computeCommitHash",
        "stateMutability": "view",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "solver", "type": "address"},
            {"name": "solutionKind", "type": "uint8"},
            {"name": "proofFormat", "type": "uint8"},
            {"name": "solutionDigest", "type": "bytes32"},
            {"name": "salt", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "revealSolution",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "submissionId", "type": "uint256"},
            {"name": "solutionKind", "type": "uint8"},
            {"name": "proofFormat", "type": "uint8"},
            {"name": "solutionDigest", "type": "bytes32"},
            {"name": "salt", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "attest",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "submissionId", "type": "uint256"},
            {"name": "support", "type": "bool"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getSubmission",
        "stateMutability": "view",
        "inputs": [
            {"name": "bountyId", "type": "uint256"},
            {"name": "submissionId", "type": "uint256"},
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "solver", "type": "address"},
                    {"name": "commitHash", "type": "bytes32"},
                    {"name": "solutionDigest", "type": "bytes32"},
                    {"name": "solutionKind", "type": "uint8"},
                    {"name": "proofFormat", "type": "uint8"},
                    {"name": "bondToken", "type": "address"},
                    {"name": "solverBond", "type": "uint256"},
                    {"name": "committedAt", "type": "uint64"},
                    {"name": "revealedAt", "type": "uint64"},
                    {"name": "quorumReachedAt", "type": "uint64"},
                    {"name": "forVotes", "type": "uint16"},
                    {"name": "againstVotes", "type": "uint16"},
                    {"name": "bondSettled", "type": "bool"},
                    {"name": "bondSlashed", "type": "bool"},
                    {"name": "state", "type": "uint8"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "getBounty",
        "stateMutability": "view",
        "inputs": [{"name": "bountyId", "type": "uint256"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "issuer", "type": "address"},
                    {"name": "paymentToken", "type": "address"},
                    {"name": "instanceCID", "type": "string"},
                    {"name": "instanceDigest", "type": "bytes32"},
                    {"name": "metadataURI", "type": "string"},
                    {"name": "metadataDigest", "type": "bytes32"},
                    {"name": "reward", "type": "uint256"},
                    {"name": "verifierRewardPool", "type": "uint256"},
                    {"name": "postingFee", "type": "uint256"},
                    {"name": "commitDeadline", "type": "uint64"},
                    {"name": "revealDeadline", "type": "uint64"},
                    {"name": "verificationDeadline", "type": "uint64"},
                    {"name": "verifierQuorum", "type": "uint16"},
                    {"name": "submissionCount", "type": "uint256"},
                    {"name": "acceptedCandidateCount", "type": "uint256"},
                    {"name": "finalized", "type": "bool"},
                    {"name": "postingFeeRouted", "type": "bool"},
                ],
            }
        ],
    },
    {
        "type": "event",
        "name": "SolutionRevealed",
        "anonymous": False,
        "inputs": [
            {"name": "bountyId", "type": "uint256", "indexed": True},
            {"name": "submissionId", "type": "uint256", "indexed": True},
            {"name": "solver", "type": "address", "indexed": True},
            {"name": "solutionDigest", "type": "bytes32", "indexed": False},
            {"name": "solutionKind", "type": "uint8", "indexed": False},
            {"name": "proofFormat", "type": "uint8", "indexed": False},
        ],
    },
    {
        "type": "function",
        "name": "verifierRewardPoolFor",
        "stateMutability": "view",
        "inputs": [{"name": "reward", "type": "uint256"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "verifierRewardBps",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint16"}],
    },
    {
        "type": "function",
        "name": "solverBondForToken",
        "stateMutability": "view",
        "inputs": [{"name": "paymentToken", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "bountySolverBond",
        "stateMutability": "view",
        "inputs": [{"name": "bountyId", "type": "uint256"}],
        "outputs": [{"name": "bondAmount", "type": "uint256"}],
    },
]


def _encode_contract_call(abi: list[dict[str, Any]], function_name: str, args: list[Any]) -> str:
    contract = Web3().eth.contract(abi=abi)
    encode_abi = getattr(contract, "encode_abi", None)
    if callable(encode_abi):
        return str(encode_abi(function_name, args=args))
    # web3.py 6.x used the camelCase spelling; it was renamed in 7.x.
    return str(contract.encodeABI(fn_name=function_name, args=args))


def encode_approval_data(spender: str, amount: int) -> str:
    return _encode_contract_call(
        ERC20_ABI,
        "approve",
        [Web3.to_checksum_address(spender), int(amount)],
    )


def encode_create_bounty_data(
    *,
    payment_token: str,
    instance_ref: str,
    instance_digest: str,
    metadata_ref: str,
    metadata_digest: str,
    reward: int,
    posting_fee: int,
    commit_window: int,
    reveal_window: int,
    verification_window: int,
    verifier_quorum: int,
) -> str:
    return _encode_contract_call(
        BOUNTY_MANAGER_ABI,
        "createBounty",
        [
            Web3.to_checksum_address(payment_token),
            str(instance_ref),
            instance_digest,
            str(metadata_ref),
            metadata_digest,
            int(reward),
            int(posting_fee),
            int(commit_window),
            int(reveal_window),
            int(verification_window),
            int(verifier_quorum),
        ],
    )


def encode_commit_solution_data(bounty_id: int | str, commit_hash: str) -> str:
    return _encode_contract_call(
        BOUNTY_MANAGER_ABI,
        "commitSolution",
        [int(bounty_id), commit_hash],
    )


def encode_reveal_solution_data(
    *,
    bounty_id: int | str,
    submission_id: int | str,
    solution_kind: int,
    proof_format: int,
    solution_digest: str,
    salt: str,
) -> str:
    return _encode_contract_call(
        BOUNTY_MANAGER_ABI,
        "revealSolution",
        [
            int(bounty_id),
            int(submission_id),
            int(solution_kind),
            int(proof_format),
            solution_digest,
            salt,
        ],
    )


def compute_solution_commit_hash(
    *,
    chain_id: int,
    bounty_manager: str,
    bounty_id: int | str,
    solver: str,
    solution_kind: int,
    proof_format: int,
    solution_digest: str,
    salt: str,
) -> str:
    if not Web3.is_address(bounty_manager) or not Web3.is_address(solver):
        raise ValueError("Commitment domain requires valid manager and solver addresses.")
    try:
        digest_bytes = bytes.fromhex(solution_digest[2:])
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("Solution digest must be a 32-byte hex value.") from error
    try:
        salt_bytes = bytes.fromhex(salt[2:])
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("Salt must be a 32-byte hex value.") from error
    if not isinstance(solution_digest, str) or not solution_digest.startswith("0x") or len(digest_bytes) != 32:
        raise ValueError("Solution digest must be a 32-byte hex value.")
    if not isinstance(salt, str) or not salt.startswith("0x") or len(salt_bytes) != 32:
        raise ValueError("Salt must be a 32-byte hex value.")
    encoded = Web3().codec.encode(
        ["uint256", "address", "uint256", "address", "uint8", "uint8", "bytes32", "bytes32"],
        [
            int(chain_id),
            Web3.to_checksum_address(bounty_manager),
            int(bounty_id),
            Web3.to_checksum_address(solver),
            int(solution_kind),
            int(proof_format),
            digest_bytes,
            salt_bytes,
        ],
    )
    digest = Web3.keccak(encoded).hex()
    return digest if digest.startswith("0x") else f"0x{digest}"


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

    def bounty_manager_contract(self, address: str):
        return self.w3.eth.contract(address=self.w3.to_checksum_address(address), abi=BOUNTY_MANAGER_ABI)

    def contract_code_size(self, address: str) -> int:
        return len(self.w3.eth.get_code(self.w3.to_checksum_address(address)))

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

    def access_quote(self, controller: str, bounty_id: str | int, payment_token: str) -> tuple[int, int, int]:
        contract = self.artifact_access_contract(controller)
        epoch, status, price = contract.functions.accessQuoteWithEpoch(
            int(bounty_id),
            SOLUTION_ARTIFACT_TYPE,
            self.w3.to_checksum_address(payment_token),
        ).call()
        return int(epoch), int(status), int(price)

    def verifier_reward_pool_for(self, bounty_manager: str, reward: int) -> int:
        return int(self.bounty_manager_contract(bounty_manager).functions.verifierRewardPoolFor(int(reward)).call())

    def verifier_reward_bps(self, bounty_manager: str) -> int:
        return int(self.bounty_manager_contract(bounty_manager).functions.verifierRewardBps().call())

    def solver_bond_for_token(self, bounty_manager: str, payment_token: str) -> int:
        return int(
            self.bounty_manager_contract(bounty_manager)
            .functions.solverBondForToken(self.w3.to_checksum_address(payment_token))
            .call()
        )

    def bounty_solver_bond(self, bounty_manager: str, bounty_id: str | int) -> int:
        return int(
            self.bounty_manager_contract(bounty_manager)
            .functions.bountySolverBond(int(bounty_id))
            .call()
        )

    def bounty_payment_token(self, bounty_manager: str, bounty_id: str | int) -> str:
        bounty = self.bounty_manager_contract(bounty_manager).functions.getBounty(int(bounty_id)).call()
        return str(bounty[1])

    def submission_identity(
        self,
        bounty_manager: str,
        bounty_id: str | int,
        submission_id: str | int,
    ) -> tuple[str, str]:
        contract = self.bounty_manager_contract(bounty_manager)
        submission = contract.functions.getSubmission(int(bounty_id), int(submission_id)).call()
        return str(submission[0]), Web3.to_hex(submission[1])

    def approval_data(self, token: str, spender: str, amount: int) -> str:
        _ = self.w3.to_checksum_address(token)
        return encode_approval_data(spender, amount)

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

    def purchase_access(
        self,
        controller: str,
        bounty_id: str | int,
        payment_token: str,
        max_price: int,
        expected_manager_epoch: int,
        private_key: str,
    ) -> dict[str, Any]:
        contract = self.artifact_access_contract(controller)
        account = self.account(private_key)
        latest_block = self.w3.eth.get_block("latest")
        deadline = int(latest_block["timestamp"]) + ACCESS_PURCHASE_DEADLINE_SECONDS
        fn = contract.functions.purchaseAccess(
            int(bounty_id),
            SOLUTION_ARTIFACT_TYPE,
            self.w3.to_checksum_address(payment_token),
            int(max_price),
            deadline,
            int(expected_manager_epoch),
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
    signature = signed.signature.hex()
    if not signature.startswith("0x"):
        signature = f"0x{signature}"
    return {"wallet": account.address, "timestamp": timestamp, "signature": signature, "message": message}


def solution_upload_auth_message(
    *,
    action: str,
    wallet: str,
    file_name: str,
    size: int,
    digest: str,
    solution_kind: int,
    proof_format: int,
    timestamp: str,
    chain_id: int,
    bounty_manager: str,
    upload_id: str,
    token_hash: str,
) -> str:
    if action not in {"reserve", "complete"}:
        raise ValueError("Solution upload action must be reserve or complete.")
    if not upload_id:
        raise ValueError("Solution upload signatures require an upload id.")
    if len(token_hash) != 66 or not token_hash.startswith("0x"):
        raise ValueError("Solution upload signatures require a 32-byte token hash.")
    return "\n".join(
        [
            "3SAT Solution Artifact Upload",
            f"action: {action}",
            f"chainId: {chain_id}",
            f"bountyManager: {bounty_manager.lower()}",
            f"wallet: {wallet.lower()}",
            f"uploadId: {upload_id}",
            f"tokenHash: {token_hash.lower()}",
            f"solutionKind: {solution_kind}",
            f"proofFormat: {proof_format}",
            f"digest: {digest.lower()}",
            f"size: {size}",
            f"fileNameUtf8: 0x{file_name.encode('utf-8').hex()}",
            f"timestamp: {timestamp}",
        ]
    )


def sign_solution_upload_message(
    private_key: str,
    *,
    action: str,
    chain_id: int,
    bounty_manager: str,
    file_name: str,
    size: int,
    digest: str,
    solution_kind: int,
    proof_format: int,
    upload_id: str,
    token_hash: str,
) -> dict[str, str]:
    account = Account.from_key(private_key)
    timestamp = str(int(time.time() * 1000))
    message = solution_upload_auth_message(
        action=action,
        wallet=account.address,
        upload_id=upload_id,
        token_hash=token_hash,
        file_name=file_name,
        size=size,
        digest=digest,
        solution_kind=solution_kind,
        proof_format=proof_format,
        timestamp=timestamp,
        chain_id=chain_id,
        bounty_manager=bounty_manager,
    )
    signed = Account.sign_message(encode_defunct(text=message), private_key)
    signature = signed.signature.hex()
    if not signature.startswith("0x"):
        signature = f"0x{signature}"
    return {
        "wallet": account.address,
        "timestamp": timestamp,
        "signature": signature,
        "message": message,
    }
