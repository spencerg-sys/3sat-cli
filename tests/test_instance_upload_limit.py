from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from threesat_cli.api import MAXIMUM_INSTANCE_UPLOAD_BYTES, ProtocolApi
from threesat_cli.main import command_issue


class InstanceUploadLimitTests(unittest.TestCase):
    def test_api_rejects_instance_over_4_mib_before_reading_or_posting(self) -> None:
        api = ProtocolApi("https://example.test")
        api.session.post = Mock()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "problem.cnf")
            with path.open("wb") as output:
                output.truncate(MAXIMUM_INSTANCE_UPLOAD_BYTES + 1)

            with self.assertRaisesRegex(RuntimeError, r"4 MiB"):
                api.upload_file("instance", path, content_type="text/plain")

        api.session.post.assert_not_called()

    def test_metadata_is_not_restricted_by_the_instance_limit(self) -> None:
        api = ProtocolApi("https://example.test")
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.reason = "OK"
        response.text = '{"ref":"r2://bucket/metadata/example.json"}'
        response.headers = {"content-type": "application/json"}
        response.json.return_value = {"ref": "r2://bucket/metadata/example.json"}
        api.session.post = Mock(return_value=response)
        content = b"x" * (MAXIMUM_INSTANCE_UPLOAD_BYTES + 1)

        result = api.upload_file(
            "metadata",
            Path("unused.json"),
            content=content,
            file_name="metadata.json",
            content_type="application/json",
        )

        self.assertEqual(result["ref"], "r2://bucket/metadata/example.json")
        api.session.post.assert_called_once()

    def test_issue_rejects_oversized_instance_before_loading_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "problem.cnf")
            with path.open("wb") as output:
                output.truncate(MAXIMUM_INSTANCE_UPLOAD_BYTES + 1)
            args = argparse.Namespace(quorum=1, cnf=str(path))

            with patch("threesat_cli.main.load_config") as load_config:
                with self.assertRaisesRegex(RuntimeError, r"4 MiB"):
                    command_issue(args)

        load_config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
