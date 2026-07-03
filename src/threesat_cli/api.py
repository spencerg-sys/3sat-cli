from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ProtocolApi:
    def __init__(self, api_url: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=None,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.api_url}{path}"

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        response = self.session.get(self._url(path), params=params, timeout=60)
        return self._decode(response)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        response = self.session.post(self._url(path), json=payload, timeout=90)
        return self._decode(response)

    def upload_file(
        self,
        kind: str,
        file_path: Path,
        *,
        content: bytes | None = None,
        file_name: str | None = None,
        content_type: str = "application/octet-stream",
        solution_kind: int | str | None = None,
        proof_format: int | str | None = None,
    ) -> Any:
        payload = content if content is not None else file_path.read_bytes()
        name = file_name or file_path.name
        data: dict[str, str] = {"kind": kind}
        if solution_kind is not None:
            data["solutionKind"] = str(solution_kind)
        if proof_format is not None:
            data["proofFormat"] = str(proof_format)
        files = {"file": (name, payload, content_type)}
        response = self.session.post(self._url("/api/protocol/storage"), data=data, files=files, timeout=120)
        return self._decode(response)

    def download_answer(
        self,
        *,
        bounty_id: str,
        wallet: str,
        timestamp: str,
        signature: str,
        query_text: str | None,
    ) -> tuple[bytes, str | None]:
        if query_text:
            response = self.session.post(
                self._url("/api/protocol/bundles/answer"),
                json={
                    "bountyId": bounty_id,
                    "wallet": wallet,
                    "timestamp": timestamp,
                    "signature": signature,
                    "queryText": query_text,
                },
                timeout=120,
            )
        else:
            response = self.session.get(
                self._url("/api/protocol/bundles/answer"),
                params={
                    "bountyId": bounty_id,
                    "wallet": wallet,
                    "timestamp": timestamp,
                    "signature": signature,
                },
                timeout=120,
            )
        if not response.ok:
            self._decode(response)
        return response.content, response.headers.get("content-disposition")

    def standardize(self, text: str) -> Any:
        return self.post("/api/protocol/sdk/cnf/standardize", {"text": text})

    def search(self, text: str) -> Any:
        return self.post("/api/protocol/search", {"text": text})

    def bounty(self, bounty_id_or_code: str) -> Any:
        return self.get(f"/api/protocol/sdk/bounties/{quote(bounty_id_or_code)}")

    def marketplace(self, sync: bool = False) -> Any:
        return self.get("/api/protocol/marketplace", params={"sync": "1"} if sync else None)

    def build_metadata(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/issuer/build-metadata", payload)

    def prepare_create_bounty(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/issuer/prepare-create-bounty", payload)

    @staticmethod
    def _decode(response: requests.Response) -> Any:
        body = response.text
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = response.json()
        else:
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                payload = {"error": body or response.reason}
        if not response.ok:
            raise RuntimeError(payload.get("error") or f"HTTP {response.status_code}: {response.reason}")
        return payload
