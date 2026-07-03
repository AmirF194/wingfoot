"""End-to-end: the reference verifier really returns 403 unsigned, 200 signed."""
from botpass import http as _http
from botpass.keys import ephemeral_identity
from botpass.rfc9421 import sign_request
from botpass.verifier import demo, start_verifier


def test_demo_flips_403_to_200():
    assert demo() is True


def test_verifier_over_http_403_then_200():
    ident = ephemeral_identity(agent_url="")
    server = start_verifier(port=0, local_jwks=[ident.jwk], trust_local_only=True)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        ident.agent_url = base

        unsigned = _http.request(f"{base}/whoami")
        assert unsigned.status == 403
        assert unsigned.json()["verified"] is False

        signed = sign_request(f"{base}/whoami", ident.private_key, ident.keyid, base)
        resp = _http.request(f"{base}/whoami", headers=signed.headers)
        assert resp.status == 200
        assert resp.json()["verified"] is True
        assert resp.json()["keyid"] == ident.keyid
    finally:
        server.shutdown()


def test_verifier_serves_directory():
    ident = ephemeral_identity(agent_url="")
    server = start_verifier(port=0, local_jwks=[ident.jwk], trust_local_only=True)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        jwks = _http.fetch_json(f"{base}/.well-known/http-message-signatures-directory")
        assert any(k["kid"] == ident.keyid for k in jwks["keys"])
    finally:
        server.shutdown()
