"""Tiny stdlib HTTP helpers so wingfoot has no runtime deps beyond `cryptography`."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__

# urllib's default User-Agent ("Python-urllib/x.y") is blocked outright by many
# CDNs (Cloudflare, Akamai) as an unidentified bot — which would make a
# verified-bot tool fail before it even gets to prove its identity. Send a
# descriptive UA instead; callers can override it via the `headers` argument.
DEFAULT_USER_AGENT = f"wingfoot/{__version__} (+https://github.com/AmirF194/wingfoot)"


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
    hdrs = dict(headers or {})
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = DEFAULT_USER_AGENT
    req = urllib.request.Request(url, method=method, headers=hdrs)
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
