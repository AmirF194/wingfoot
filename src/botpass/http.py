"""Tiny stdlib HTTP helpers so botpass has no runtime deps beyond `cryptography`."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def request(url: str, *, method: str = "GET", headers: dict | None = None,
            timeout: float = 10.0) -> Response:
    """Send a request, returning a Response even for 4xx/5xx (no exception)."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return Response(resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers or {}), exc.read())


def fetch_json(url: str, timeout: float = 5.0) -> dict:
    resp = request(url, timeout=timeout)
    if resp.status != 200:
        raise OSError(f"{url} returned HTTP {resp.status}")
    data = resp.json()
    if data is None:
        raise ValueError(f"{url} did not return JSON")
    return data
