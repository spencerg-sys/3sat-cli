from __future__ import annotations

import json
import re
import secrets
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from web3 import Web3

MAXIMUM_INSTANCE_UPLOAD_BYTES = 4 * 1024 * 1024


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
            # Never replay non-idempotent POST requests implicitly. Direct upload
            # reservation retries are explicitly idempotent at the API contract,
            # and completion retries must carry a fresh wallet timestamp/signature.
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        if path.startswith("https://") or path.startswith("http://"):
            return path
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.api_url}{path}"

    def _is_api_url(self, url: str) -> bool:
        return urlparse(url).netloc.lower() == urlparse(self.api_url).netloc.lower()

    def _post_idempotent_reservation(
        self, path: str, payload: dict[str, Any], *, timeout: int
    ) -> requests.Response:
        last_error: requests.RequestException | None = None
        for attempt in range(4):
            try:
                response = self.session.post(self._url(path), json=payload, timeout=timeout)
            except requests.RequestException as error:
                last_error = error
                if attempt == 3:
                    raise
            else:
                if response.status_code not in {429, 500, 502, 503, 504} or attempt == 3:
                    return response
                retry_after = response.headers.get("retry-after", "")
                try:
                    delay = min(10.0, max(0.25, float(retry_after)))
                except ValueError:
                    delay = min(4.0, 0.5 * (2**attempt))
                time.sleep(delay)
                continue
            time.sleep(min(4.0, 0.5 * (2**attempt)))
        if last_error is not None:
            raise last_error
        raise RuntimeError("Idempotent upload reservation did not return a response.")

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
    ) -> Any:
        if kind not in {"instance", "metadata"}:
            raise RuntimeError("SAT assignments and UNSAT proofs must use the authenticated upload flow.")
        if kind == "instance":
            instance_size = len(content) if content is not None else file_path.stat().st_size
            if instance_size > MAXIMUM_INSTANCE_UPLOAD_BYTES:
                raise RuntimeError("Instance CNF files must be 4 MiB or smaller.")
        payload = content if content is not None else file_path.read_bytes()
        name = file_name or file_path.name
        data: dict[str, str] = {"kind": kind}
        files = {"file": (name, payload, content_type)}
        response = self.session.post(self._url("/api/protocol/storage"), data=data, files=files, timeout=120)
        return self._decode(response)

    def initialize_solution_upload(
        self,
        *,
        upload_id: str,
        token: str,
        wallet: str,
        timestamp: str,
        signature: str,
        file_name: str,
        size: int,
        digest: str,
        solution_kind: int,
        proof_format: int,
    ) -> dict[str, Any]:
        response = self._post_idempotent_reservation(
            "/api/protocol/storage/uploads",
            {
                "uploadId": upload_id,
                "token": token,
                "wallet": wallet,
                "timestamp": timestamp,
                "signature": signature,
                "fileName": file_name,
                "size": size,
                "digest": digest,
                "solutionKind": solution_kind,
                "proofFormat": proof_format,
            },
            timeout=60,
        )
        payload = self._decode(response)
        reservation = payload.get("upload") if isinstance(payload, dict) else None
        if not isinstance(reservation, dict):
            raise RuntimeError("Direct solution upload initialization returned an invalid response.")
        if (
            reservation.get("digest") != digest
            or reservation.get("id") != upload_id
            or reservation.get("token") != token
            or reservation.get("size") != size
            or reservation.get("fileName") != file_name
            or reservation.get("solutionKind") != solution_kind
            or reservation.get("proofFormat") != proof_format
        ):
            raise RuntimeError("Direct solution upload reservation is not bound to the selected file.")
        return reservation

    def upload_reserved_solution(self, file_path: Path, reservation: dict[str, Any]) -> tuple[str, str]:
        upload_id = str(reservation.get("id") or "").strip()
        token = str(reservation.get("token") or "").strip()
        direct = reservation.get("upload")
        if not upload_id or not token or not isinstance(direct, dict):
            raise RuntimeError("Direct solution upload reservation is incomplete.")
        upload_url = str(direct.get("url") or "").strip()
        method = str(direct.get("method") or "").upper()
        raw_headers = direct.get("headers")
        parsed_url = urlparse(upload_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.netloc
            or method != "PUT"
            or not isinstance(raw_headers, dict)
        ):
            raise RuntimeError("Direct solution upload instructions are invalid.")
        headers: dict[str, str] = {}
        for key, value in raw_headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise RuntimeError("Direct solution upload headers are invalid.")
            headers[key] = value
        with file_path.open("rb") as payload:
            response = self.session.put(upload_url, data=payload, headers=headers, timeout=600)
        if not response.ok:
            raise RuntimeError(
                f"Direct solution upload failed with HTTP {response.status_code}: {response.reason}"
            )
        return upload_id, token

    def complete_solution_upload(
        self,
        *,
        upload_id: str,
        token: str,
        wallet: str,
        timestamp: str,
        signature: str,
    ) -> dict[str, Any]:
        response = self.session.post(
            self._url(f"/api/protocol/storage/uploads/{quote(upload_id)}/complete"),
            json={
                "token": token,
                "wallet": wallet,
                "timestamp": timestamp,
                "signature": signature,
            },
            timeout=600,
        )
        payload = self._decode(response)
        if not isinstance(payload, dict):
            raise RuntimeError("Direct solution upload completion returned an invalid response.")
        return payload

    def download_answer(
        self,
        *,
        bounty_id: str,
        wallet: str,
        timestamp: str,
        signature: str,
        query_file: tuple[str, bytes] | None,
        query_upload: tuple[str, str] | None = None,
        max_wait_seconds: int = 60 * 60,
    ) -> tuple[bytes, str | None]:
        if query_file is not None and query_upload is not None:
            raise RuntimeError("Matched answer download cannot use both a file and a direct upload.")
        if query_file is not None:
            query_file_name, query_bytes = query_file
            response = self.session.post(
                self._url("/api/protocol/bundles/answer"),
                data={
                    "bountyId": bounty_id,
                    "wallet": wallet,
                    "timestamp": timestamp,
                    "signature": signature,
                },
                files={"file": (query_file_name, query_bytes, "text/plain")},
                timeout=120,
            )
        elif query_upload is not None:
            upload_id, upload_token = query_upload
            response = self.session.post(
                self._url("/api/protocol/bundles/answer"),
                json={
                    "bountyId": bounty_id,
                    "wallet": wallet,
                    "timestamp": timestamp,
                    "signature": signature,
                    "uploadId": upload_id,
                    "uploadToken": upload_token,
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
        if response.status_code != 202:
            if not response.ok:
                self._decode(response)
            return response.content, response.headers.get("content-disposition")

        queued = self._decode(response)
        if not isinstance(queued, dict):
            raise RuntimeError("UNSAT transform API returned an invalid queued response.")
        job = queued.get("job")
        if not isinstance(job, dict):
            raise RuntimeError("UNSAT transform API did not return a job.")
        job_id = str(job.get("id") or "").strip()
        access_token = str(job.get("accessToken") or "").strip()
        poll_url = str(job.get("pollUrl") or "").strip()
        if not job_id or not access_token or not poll_url:
            raise RuntimeError("UNSAT transform job response is missing its id, token, or poll URL.")

        deadline = time.monotonic() + max(1, max_wait_seconds)
        poll_after_ms = self._positive_poll_delay(queued.get("pollAfterMs") or job.get("pollAfterMs"))
        authorization = {"Authorization": f"Bearer {access_token}"}

        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"UNSAT proof transform job {job_id} did not finish within {max_wait_seconds} seconds."
                )
            time.sleep(min(poll_after_ms / 1000, max(0, deadline - time.monotonic())))
            status_response = self.session.get(
                self._url(poll_url),
                headers=authorization,
                timeout=60,
            )
            status_payload = self._decode(status_response)
            if not isinstance(status_payload, dict) or not isinstance(status_payload.get("job"), dict):
                raise RuntimeError("UNSAT transform status API returned an invalid response.")
            status_job = status_payload["job"]
            status = str(status_job.get("status") or "").strip().lower()
            if status in {"queued", "processing"}:
                poll_after_ms = self._positive_poll_delay(status_payload.get("pollAfterMs"))
                continue
            if status == "failed":
                error = status_job.get("error")
                if isinstance(error, dict):
                    code = str(error.get("code") or "UNSAT_PROOF_TRANSFORM_FAILED")
                    message = str(error.get("message") or "UNSAT proof transformation failed.")
                    raise RuntimeError(f"{code}: {message}")
                raise RuntimeError("UNSAT_PROOF_TRANSFORM_FAILED: UNSAT proof transformation failed.")
            if status != "succeeded":
                raise RuntimeError(f"UNSAT transform job returned unsupported status {status or '<empty>'}.")

            output = status_job.get("output")
            if not isinstance(output, dict):
                raise RuntimeError("Completed UNSAT transform job is missing its verified output binding.")
            expected_digest = output.get("zipDigest")
            expected_size = output.get("size")
            if not isinstance(expected_digest, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", expected_digest):
                raise RuntimeError("UNSAT transform job returned an invalid output digest.")
            if (
                isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or expected_size < 1
                or expected_size > 140 * 1024 * 1024
            ):
                raise RuntimeError("UNSAT transform job returned an invalid output size.")
            expected_digest = expected_digest.lower()

            download = status_payload.get("download")
            if not isinstance(download, dict) or not str(download.get("url") or "").strip():
                raise RuntimeError("Completed UNSAT transform job did not return a download URL.")
            download_url = self._url(str(download["url"]))
            download_headers = authorization if self._is_api_url(download_url) else None
            download_response = self.session.get(
                download_url,
                headers=download_headers,
                timeout=300,
            )
            if not download_response.ok:
                self._decode(download_response)

            payload = download_response.content
            if expected_size != len(payload):
                raise RuntimeError("Downloaded UNSAT bundle size does not match the verified job output.")
            actual_digest = Web3.keccak(payload).hex().lower()
            if not actual_digest.startswith("0x"):
                actual_digest = f"0x{actual_digest}"
            if actual_digest != expected_digest:
                raise RuntimeError("Downloaded UNSAT bundle digest does not match the verified job output.")
            return payload, download_response.headers.get("content-disposition")

    def upload_unsat_transform_target(
        self,
        *,
        bounty_id: str,
        wallet: str,
        timestamp: str,
        signature: str,
        query_file: tuple[str, bytes],
    ) -> tuple[str, str]:
        file_name, payload = query_file
        upload_id = str(uuid.uuid4())
        upload_token = secrets.token_urlsafe(32)
        digest = Web3.keccak(payload).hex()
        if not digest.startswith("0x"):
            digest = f"0x{digest}"
        initialized_response = self._post_idempotent_reservation(
            "/api/protocol/unsat-transform/uploads",
            {
                "uploadId": upload_id,
                "uploadToken": upload_token,
                "bountyId": bounty_id,
                "wallet": wallet,
                "timestamp": timestamp,
                "signature": signature,
                "fileName": file_name,
                "size": len(payload),
                "digest": digest,
            },
            timeout=60,
        )
        initialized = self._decode(initialized_response)
        if not isinstance(initialized, dict) or not isinstance(initialized.get("upload"), dict):
            raise RuntimeError("UNSAT target upload initialization returned an invalid response.")
        reservation = initialized["upload"]
        reserved_upload_id = str(reservation.get("id") or "").strip()
        reserved_upload_token = str(reservation.get("token") or "").strip()
        direct = reservation.get("upload")
        if (
            reserved_upload_id != upload_id
            or reserved_upload_token != upload_token
            or str(reservation.get("digest") or "").lower() != digest.lower()
            or reservation.get("size") != len(payload)
            or not isinstance(direct, dict)
        ):
            raise RuntimeError("Target CNF upload reservation is incomplete or not bound to the selected file.")
        upload_url = str(direct.get("url") or "").strip()
        method = str(direct.get("method") or "PUT").upper()
        raw_headers = direct.get("headers")
        if not upload_url or method != "PUT" or not isinstance(raw_headers, dict):
            raise RuntimeError("Target CNF upload instructions are invalid.")
        parsed_url = urlparse(upload_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise RuntimeError("Target CNF upload URL is invalid.")
        headers = {
            str(key): str(value)
            for key, value in raw_headers.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        uploaded = self.session.put(upload_url, data=payload, headers=headers, timeout=300)
        if not uploaded.ok:
            raise RuntimeError(
                f"Direct target CNF upload failed with HTTP {uploaded.status_code}: {uploaded.reason}"
            )
        return upload_id, upload_token

    @staticmethod
    def _positive_poll_delay(value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return 2_000
        return min(max(parsed, 250), 30_000)

    def standardize(self, text: str) -> Any:
        return self.post("/api/protocol/sdk/cnf/standardize", {"text": text})

    def search(self, text: str) -> Any:
        return self.post("/api/protocol/search", {"text": text})

    def bounty(self, bounty_id_or_code: str) -> Any:
        return self.get(f"/api/protocol/sdk/bounties/{quote(bounty_id_or_code)}")

    def marketplace(self, sync: bool = False, limit: int | None = None, offset: int | None = None) -> Any:
        params: dict[str, str] = {}
        if sync:
            params["sync"] = "1"
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        return self.get("/api/protocol/marketplace", params=params or None)

    def build_metadata(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/issuer/build-metadata", payload)

    def prepare_create_bounty(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/issuer/prepare-create-bounty", payload)

    def prepare_commit(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/solver/prepare-commit", payload)

    def prepare_reveal(self, payload: dict[str, Any]) -> Any:
        return self.post("/api/protocol/sdk/solver/prepare-reveal", payload)

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
