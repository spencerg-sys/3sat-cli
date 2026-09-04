from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


CONFIG_DIR = Path(os.environ.get("THREESAT_CONFIG_DIR", Path.home() / ".3sat"))
CONFIG_PATH = Path(os.environ.get("THREESAT_CONFIG", CONFIG_DIR / "config.json"))


DEFAULT_CONFIG: dict[str, Any] = {
    "api_url": "https://3sat.network",
    "rpc_url": "https://arb1.arbitrum.io/rpc",
    "chain_id": 42161,
    "chain_name": "Arbitrum One",
    "bounty_manager": "0xD31897B472156CC31Dc64d0fa45e43bF7B8C02ED",
    "artifact_access_controller": "0xf875fDaBbC191801f8C8fD7fde968556Ca2D760f",
    "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    "sat_token": "0x2C1B789B001F51F65a9fa61C4501B0E9Fc0Ab92c",
    "tokens": {
        "USDC": {
            "symbol": "USDC",
            "address": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
            "decimals": 6,
        },
        "3SAT": {
            "symbol": "$3SAT",
            "address": "0x2C1B789B001F51F65a9fa61C4501B0E9Fc0Ab92c",
            "decimals": 18,
        },
    },
}


ENV_MAP = {
    "THREESAT_API_URL": "api_url",
    "THREESAT_RPC_URL": "rpc_url",
    "THREESAT_CHAIN_ID": "chain_id",
    "THREESAT_CHAIN_NAME": "chain_name",
    "THREESAT_BOUNTY_MANAGER_ADDRESS": "bounty_manager",
    "THREESAT_ARTIFACT_ACCESS_CONTROLLER_ADDRESS": "artifact_access_controller",
    "THREESAT_USDC_ADDRESS": "usdc",
    "THREESAT_TOKEN_ADDRESS": "sat_token",
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    output = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = _deep_merge(output[key], value)
        else:
            output[key] = value
    return output


def load_config() -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        file_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(file_config, dict):
            raise ValueError(f"{CONFIG_PATH} must contain a JSON object.")
        config = _deep_merge(config, file_config)

    for env_key, config_key in ENV_MAP.items():
        value = os.environ.get(env_key)
        if value:
            config[config_key] = int(value) if config_key == "chain_id" else value

    tokens = dict(config.get("tokens") or {})
    if config.get("usdc"):
        tokens["USDC"] = {
            **tokens.get("USDC", {}),
            "symbol": "USDC",
            "address": config["usdc"],
            "decimals": int(tokens.get("USDC", {}).get("decimals", 6)),
        }
    if config.get("sat_token"):
        tokens["3SAT"] = {
            **tokens.get("3SAT", {}),
            "symbol": "$3SAT",
            "address": config["sat_token"],
            "decimals": int(tokens.get("3SAT", {}).get("decimals", 18)),
        }
    config["tokens"] = tokens
    return config


def save_config(config: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def init_config(force: bool = False) -> Path:
    if CONFIG_PATH.exists() and not force:
        return CONFIG_PATH
    save_config(DEFAULT_CONFIG)
    return CONFIG_PATH


def set_config_value(key: str, value: str) -> Path:
    editable_keys = {
        "api_url",
        "rpc_url",
        "chain_id",
        "chain_name",
        "bounty_manager",
        "artifact_access_controller",
        "usdc",
        "sat_token",
    }
    if key not in editable_keys:
        raise ValueError(f"Unsupported config key: {key}")
    config = load_config()
    config[key] = int(value) if key == "chain_id" else value
    if key == "usdc":
        config.setdefault("tokens", {}).setdefault("USDC", {})["address"] = value
    if key == "sat_token":
        config.setdefault("tokens", {}).setdefault("3SAT", {})["address"] = value
    save_config(config)
    return CONFIG_PATH


def token_by_symbol(config: dict[str, Any], symbol: str) -> dict[str, Any]:
    normalized = symbol.upper().replace("$", "")
    if normalized not in config.get("tokens", {}):
        supported = ", ".join(config.get("tokens", {}).keys())
        raise ValueError(f"Unsupported token {symbol}. Supported: {supported}")
    return config["tokens"][normalized]


def token_by_address(config: dict[str, Any], address: str) -> dict[str, Any]:
    for token in config.get("tokens", {}).values():
        if str(token.get("address", "")).lower() == address.lower():
            return token
    return {"symbol": address, "address": address, "decimals": 18}


def private_key_from_args(value: str | None) -> str | None:
    key = value or os.environ.get("THREESAT_PRIVATE_KEY")
    if not key:
        return None
    return key if key.startswith("0x") else f"0x{key}"
