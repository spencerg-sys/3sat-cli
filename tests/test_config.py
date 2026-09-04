from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threesat_cli import config as config_module


class ConfigEnvironmentTests(unittest.TestCase):
    def test_defaults_target_arbitrum_one_production_deployment(self) -> None:
        self.assertEqual(config_module.DEFAULT_CONFIG["rpc_url"], "https://arb1.arbitrum.io/rpc")
        self.assertEqual(config_module.DEFAULT_CONFIG["chain_id"], 42161)
        self.assertEqual(config_module.DEFAULT_CONFIG["chain_name"], "Arbitrum One")
        self.assertEqual(
            config_module.DEFAULT_CONFIG["bounty_manager"],
            "0xD31897B472156CC31Dc64d0fa45e43bF7B8C02ED",
        )
        self.assertEqual(
            config_module.DEFAULT_CONFIG["artifact_access_controller"],
            "0xf875fDaBbC191801f8C8fD7fde968556Ca2D760f",
        )
        self.assertEqual(
            config_module.DEFAULT_CONFIG["tokens"]["USDC"]["address"],
            "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        )
        self.assertEqual(
            config_module.DEFAULT_CONFIG["tokens"]["3SAT"]["address"],
            "0x2C1B789B001F51F65a9fa61C4501B0E9Fc0Ab92c",
        )

    def test_threesat_environment_overrides_are_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_config = Path(temp_dir) / "missing.json"
            environment = {
                "THREESAT_API_URL": "https://api.example",
                "THREESAT_RPC_URL": "https://rpc.example",
                "THREESAT_CHAIN_ID": "31337",
                "THREESAT_CHAIN_NAME": "Local Test Chain",
                "THREESAT_BOUNTY_MANAGER_ADDRESS": "0x1111111111111111111111111111111111111111",
                "THREESAT_ARTIFACT_ACCESS_CONTROLLER_ADDRESS": "0x2222222222222222222222222222222222222222",
                "THREESAT_USDC_ADDRESS": "0x3333333333333333333333333333333333333333",
                "THREESAT_TOKEN_ADDRESS": "0x4444444444444444444444444444444444444444",
            }
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(config_module, "CONFIG_PATH", missing_config),
            ):
                loaded = config_module.load_config()

        self.assertEqual(loaded["api_url"], environment["THREESAT_API_URL"])
        self.assertEqual(loaded["rpc_url"], environment["THREESAT_RPC_URL"])
        self.assertEqual(loaded["chain_id"], 31337)
        self.assertEqual(loaded["chain_name"], "Local Test Chain")
        self.assertEqual(loaded["bounty_manager"], environment["THREESAT_BOUNTY_MANAGER_ADDRESS"])
        self.assertEqual(
            loaded["artifact_access_controller"],
            environment["THREESAT_ARTIFACT_ACCESS_CONTROLLER_ADDRESS"],
        )
        self.assertEqual(loaded["tokens"]["USDC"]["address"], environment["THREESAT_USDC_ADDRESS"])
        self.assertEqual(loaded["tokens"]["3SAT"]["address"], environment["THREESAT_TOKEN_ADDRESS"])

    def test_old_numeric_prefix_is_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_config = Path(temp_dir) / "missing.json"
            with (
                patch.dict(os.environ, {"3SAT_RPC_URL": "https://legacy.invalid"}, clear=True),
                patch.object(config_module, "CONFIG_PATH", missing_config),
            ):
                loaded = config_module.load_config()

        self.assertEqual(loaded["rpc_url"], config_module.DEFAULT_CONFIG["rpc_url"])

    def test_private_key_uses_threesat_prefix_and_argument_takes_precedence(self) -> None:
        with patch.dict(os.environ, {"THREESAT_PRIVATE_KEY": "abcd"}, clear=True):
            self.assertEqual(config_module.private_key_from_args(None), "0xabcd")
            self.assertEqual(config_module.private_key_from_args("1234"), "0x1234")


if __name__ == "__main__":
    unittest.main()
