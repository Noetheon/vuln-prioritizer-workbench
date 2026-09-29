"""Client that imports a scanner or SBOM file through a running Workbench API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TERMINAL_RUN_STATUSES = frozenset(
    {"succeeded", "completed", "completed_with_errors", "failed", "cancelled"}
)
SUCCESSFUL_RUN_STATUSES = frozenset({"succeeded", "completed", "completed_with_errors"})


class ImportClientError(RuntimeError):
    """Raised when the Workbench cannot be reached or rejects the import."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Status and body of one HTTP exchange."""

    status: int
    body: bytes

    def json(self) -> Any:
        """Decode a JSON body."""
        return json.loads(self.body.decode("utf-8")) if self.body else None


Transport = Callable[[str, str, bytes | None, Mapping[str, str]], HttpResponse]


def urllib_transport(timeout_seconds: float = 60.0) -> Transport:
    """Return a transport that talks to a Workbench over HTTP."""

    def send(method: str, url: str, body: bytes | None, headers: Mapping[str, str]) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
                return HttpResponse(status=response.status, body=response.read())
        except urllib.error.HTTPError as exc:
            return HttpResponse(status=exc.code, body=exc.read())
        except (urllib.error.URLError, OSError) as exc:
            raise ImportClientError(
                f"Cannot reach the Workbench at {url}: {getattr(exc, 'reason', exc)}. "
                "Start it with `vpw serve` or pass --url."
            ) from exc

    return send


@dataclass(frozen=True, slots=True)
class ImportRequest:
    """One file to import and how."""

    file: Path
    input_type: str
    asset_context_file: Path | None = None
    vex_file: Path | None = None
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    resolve_missing: bool = True


class WorkbenchImportClient:
    """Resolve a project, upload one import, and wait for its run to finish."""

    def __init__(
        self,
        base_url: str,
        transport: Transport,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        """
        Bind the client to a Workbench base URL such as http://127.0.0.1:8765.

        ``extra_headers`` go with every request, for example the credentials a
        team-mode login proxy expects from automation.
        """
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self._extra_headers = dict(extra_headers or {})

    def resolve_project(self, project: str, *, create: bool = False) -> dict[str, Any]:
        """Return the project with this id or exact name, creating it when asked."""
        projects = self._request("GET", "/api/v1/projects/?limit=500").get("data") or []
        wanted = project.strip()
        for item in projects:
            if str(item.get("id")) == wanted:
                return dict(item)
        matches = [item for item in projects if str(item.get("name", "")).strip() == wanted]
        if len(matches) == 1:
            return dict(matches[0])
        if len(matches) > 1:
            raise ImportClientError(f"Several projects are named {wanted!r}; pass the project id.")
        if create:
            created = self._request(
                "POST",
                "/api/v1/projects/",
                body=json.dumps({"name": wanted, "description": None}).encode(),
                headers={"Content-Type": "application/json"},
            )
            return dict(created)
        names = ", ".join(sorted(str(item.get("name")) for item in projects)) or "none"
        raise ImportClientError(
            f"No project named {wanted!r}. Existing projects: {names}. "
            "Pass --create-project to create it."
        )

    def start_import(self, project_id: str, request: ImportRequest) -> dict[str, Any]:
        """Upload the file and return the queued run."""
        fields = {
            "input_type": request.input_type,
            "locked_provider_data": _form_bool(request.locked_provider_data),
            "resolve_missing": _form_bool(request.resolve_missing),
        }
        if request.provider_snapshot_file:
            fields["provider_snapshot_file"] = request.provider_snapshot_file
        files = {"file": request.file}
        if request.asset_context_file is not None:
            files["asset_context_file"] = request.asset_context_file
        if request.vex_file is not None:
            files["vex_file"] = request.vex_file
        body, content_type = _multipart(fields, files)
        path = f"/api/v1/projects/{urllib.parse.quote(project_id)}/imports"
        return dict(self._request("POST", path, body=body, headers={"Content-Type": content_type}))

    def wait_for_run(
        self,
        run_id: str,
        *,
        timeout_seconds: float,
        poll_seconds: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> dict[str, Any]:
        """Poll the run until it reaches a terminal status and return its summary."""
        deadline = clock() + timeout_seconds
        quoted = urllib.parse.quote(run_id)
        while True:
            run = self._request("GET", f"/api/v1/runs/{quoted}")
            if str(run.get("status")) in TERMINAL_RUN_STATUSES:
                return dict(self._request("GET", f"/api/v1/runs/{quoted}/summary"))
            if clock() >= deadline:
                raise ImportClientError(
                    f"Run {run_id} is still {run.get('status')} after {timeout_seconds:g}s; "
                    "it keeps running in the Workbench."
                )
            sleep(poll_seconds)

    def run_url(self, run: Mapping[str, Any]) -> str:
        """Return the browser link to a run."""
        query = urllib.parse.urlencode({"projectId": run.get("project_id", "")})
        return f"{self.base_url}/imports/runs/{run.get('id')}?{query}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self._transport(
            method,
            f"{self.base_url}{path}",
            body,
            {"Accept": "application/json", **self._extra_headers, **(headers or {})},
        )
        if response.status >= 400:
            raise ImportClientError(
                f"{method} {path} failed with HTTP {response.status}: {_error_detail(response)}"
            )
        return response.json() or {}


def parse_header_option(value: str) -> tuple[str, str]:
    """Split a ``Name: value`` command-line header, rejecting malformed input."""
    name, separator, header_value = value.partition(":")
    name = name.strip()
    if not separator or not name or any(character in name for character in " \t\r\n"):
        raise ImportClientError(f"Headers must look like 'Name: value', got {value!r}.")
    if any(character in header_value for character in "\r\n"):
        raise ImportClientError(f"Header {name} must not contain line breaks.")
    return name, header_value.strip()


def _form_bool(value: bool) -> str:
    return "true" if value else "false"


def _multipart(fields: Mapping[str, str], files: Mapping[str, Path]) -> tuple[bytes, str]:
    boundary = f"vpw-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value.encode("utf-8")
            + b"\r\n"
        )
    for name, path in files.items():
        filename = urllib.parse.quote(path.name, safe=" ._-()")
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + path.read_bytes()
            + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _error_detail(response: HttpResponse) -> str:
    try:
        payload = response.json()
    except (ValueError, UnicodeDecodeError):
        return response.body[:300].decode("utf-8", errors="replace")
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("message") or detail)
        if detail is not None:
            return str(detail)
    return str(payload)[:300]
