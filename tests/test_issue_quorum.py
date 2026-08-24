from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from threesat_cli.main import build_parser, command_issue


class IssueQuorumTests(unittest.TestCase):
    def test_parser_defaults_quorum_to_one(self) -> None:
        args = build_parser().parse_args(["issue", "problem.cnf", "--reward", "1"])

        self.assertEqual(args.quorum, 1)

    def test_parser_accepts_explicit_quorum_one(self) -> None:
        args = build_parser().parse_args(
            ["issue", "problem.cnf", "--reward", "1", "--quorum", "1"]
        )

        self.assertEqual(args.quorum, 1)

    def test_parser_rejects_non_one_quorum(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                build_parser().parse_args(
                    ["issue", "problem.cnf", "--reward", "1", "--quorum", "2"]
                )

        self.assertEqual(error.exception.code, 2)

    def test_command_rejects_non_one_before_loading_config(self) -> None:
        args = argparse.Namespace(quorum=2)

        with patch("threesat_cli.main.load_config") as load_config:
            with self.assertRaisesRegex(
                RuntimeError,
                r"Verifier quorum is temporarily fixed at 1; --quorum must be 1\.",
            ):
                command_issue(args)

        load_config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
