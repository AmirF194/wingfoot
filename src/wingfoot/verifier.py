"""A reference Web Bot Auth verifier you can test against.

Unsigned or invalid requests get 403; a correctly signed and verified request gets 200.
It serves its own JWKS at the well-known path, so a single process can host the demo.
The `demo()` helper runs the unsigned/signed flow in-process, no setup required.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import DIRECTORY_PATH
from . import http as _http
from .directory import build_directory, directory_url_for, find_key
from .keys import ephemeral_identity
from .rfc9421 import sign_request, verify_request


def _make_handler(local_jwks: list[dict], trust_local_only: bool):
    def resolve_key(keyid: str, agent_url: Optional[str]):
        # Fast path: a key we host locally (used by the self-contained demo).
        key = find_key({"keys": local_jwks}, keyid)
        if key is not None:
            return key
        if trust_local_only or not agent_url:
            return None
        # Otherwise fetch the signer's advertised directory and look up the key.
        try:
            jwks_doc = _http.fetch_json(directory_url_for(agent_url))
        except Exception:
            return None
        return find_key(jwks_doc, keyid)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep the demo output clean
            pass

        def _send(self, status: int, payload: dict):
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == DIRECTORY_PATH:
                body = json.dumps(build_directory(local_jwks), indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/http-message-signatures-directory+json")
                self.send_header("Cache-Control", "max-age=86400")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._verify_and_respond()

        do_POST = do_GET
        do_PUT = do_GET
        do_DELETE = do_GET

        def _verify_and_respond(self):
            host = self.headers.get("Host", "127.0.0.1")
            url = f"http://{host}{self.path}"
            headers = {k: v for k, v in self.headers.items()}
            result = verify_request(url, headers, resolve_key)
            if result.ok:
                self._send(200, {
                    "verified": True,
                    "keyid": result.keyid,
                })
            else:
                self._send(403, {
                    "verified": False,
                    "reason": result.reason,
                    "checks": [
                        {"name": n, "ok": ok, "detail": d} for (n, ok, d) in result.checks
                    ],
                })

    return Handler


def start_verifier(port: int = 0, local_jwks: Optional[list[dict]] = None,
                   trust_local_only: bool = False) -> ThreadingHTTPServer:
    """Start a verifier in a background thread. Returns the server (call shutdown())."""
    handler = _make_handler(local_jwks or [], trust_local_only)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def demo() -> bool:
    """Run the full 403 -> 200 flow in one process. Returns True on success."""
    identity = ephemeral_identity(agent_url="")  # agent_url filled in once we know the port
    server = start_verifier(port=0, local_jwks=[identity.jwk], trust_local_only=True)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    identity.agent_url = base

    C = _Colors()
    print(f"{C.dim}Reference verifier listening on {base}{C.reset}\n")

    # 1) Unsigned request: what an un-verified bot sees.
    print(f"{C.bold}1. Unsigned request{C.reset}")
    unsigned = _http.request(f"{base}/whoami")
    print(f"   HTTP {_status(unsigned.status, C)}  "
          f"{C.dim}{(unsigned.json() or {}).get('reason','')}{C.reset}\n")

    # 2) Signed request: the same request with a Web Bot Auth signature.
    print(f"{C.bold}2. Signed request{C.reset}")
    signed = sign_request(f"{base}/whoami", identity.private_key, identity.keyid, base)
    resp = _http.request(f"{base}/whoami", headers=signed.headers)
    body = resp.json() or {}
    print(f"   HTTP {_status(resp.status, C)}  "
          f"{C.dim}verified (keyid {(body.get('keyid') or '')[:12]}...){C.reset}\n")

    server.shutdown()
    ok = unsigned.status == 403 and resp.status == 200
    if ok:
        print(f"{C.green}Signing changed HTTP 403 to 200.{C.reset}")
    else:
        print(f"{C.red}Expected 403 then 200, got "
              f"{unsigned.status} then {resp.status}.{C.reset}")
    return ok


def _status(code: int, C) -> str:
    color = C.green if code == 200 else (C.red if code >= 400 else C.reset)
    label = "200 OK" if code == 200 else ("403 Forbidden" if code == 403 else str(code))
    return f"{color}{label}{C.reset}"


class _Colors:
    def __init__(self):
        import os, sys
        on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.reset = "\033[0m" if on else ""
        self.bold = "\033[1m" if on else ""
        self.dim = "\033[2m" if on else ""
        self.green = "\033[32m" if on else ""
        self.red = "\033[31m" if on else ""
        self.yellow = "\033[33m" if on else ""
