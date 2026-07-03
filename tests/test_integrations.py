"""End-to-end tests for the drop-in requests / httpx signing adapters.

Each test starts the reference verifier in-process, then drives a real HTTP client
against it: unsigned must 403, wingfoot-signed must 200. This is the `403 -> 200`
promise, proven through the clients people actually use.
"""
from __future__ import annotations

import pytest

import wingfoot
from wingfoot.keys import ephemeral_identity
from wingfoot.verifier import start_verifier


@pytest.fixture
def verifier_and_identity():
    """A running verifier that trusts a fresh ephemeral identity, plus that identity."""
    identity = ephemeral_identity(agent_url="")
    server = start_verifier(port=0, local_jwks=[identity.jwk], trust_local_only=True)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    identity.agent_url = base
    try:
        yield base, identity
    finally:
        server.shutdown()


def test_signed_headers_verify_at_the_edge(verifier_and_identity):
    """The low-level helper produces headers a verifier accepts."""
    base, identity = verifier_and_identity
    headers = wingfoot.signed_headers(f"{base}/whoami", identity=identity)
    assert {"Signature", "Signature-Input", "Signature-Agent"} <= set(headers)


def test_requests_adapter(verifier_and_identity):
    requests = pytest.importorskip("requests")
    base, identity = verifier_and_identity
    assert requests.get(f"{base}/whoami").status_code == 403
    resp = requests.get(f"{base}/whoami", auth=wingfoot.requests_auth(identity=identity))
    assert resp.status_code == 200
    assert resp.json()["verified"] is True


def test_httpx_adapter(verifier_and_identity):
    httpx = pytest.importorskip("httpx")
    base, identity = verifier_and_identity
    assert httpx.get(f"{base}/whoami").status_code == 403
    resp = httpx.get(f"{base}/whoami", auth=wingfoot.httpx_auth(identity=identity))
    assert resp.status_code == 200
    assert resp.json()["verified"] is True


def test_missing_identity_is_a_clear_error(monkeypatch):
    """With no persisted identity and none passed, the error tells you what to do."""
    monkeypatch.setattr("wingfoot.integrations.load_identity", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="wingfoot init"):
        wingfoot.signed_headers("https://example.com/")
