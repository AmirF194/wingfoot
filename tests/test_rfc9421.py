"""RFC 9421 / Web Bot Auth signing + verification round-trips."""
import time

from wingfoot.keys import ephemeral_identity, generate_private_key, keyid_for
from wingfoot.rfc9421 import (
    authority_of,
    build_signature_base,
    parse_signature,
    sign_request,
    verify_request,
)


def _resolver_for(identity):
    return lambda keyid, agent: identity.public_key if keyid == identity.keyid else None


def test_authority_strips_default_ports():
    assert authority_of("https://Example.com/path") == "example.com"
    assert authority_of("http://example.com:80/x") == "example.com"
    assert authority_of("https://example.com:8443/x") == "example.com:8443"


def test_sign_then_verify_roundtrip():
    ident = ephemeral_identity("https://bot.example")
    url = "https://api.example.com/data"
    signed = sign_request(url, ident.private_key, ident.keyid, ident.agent_url)
    result = verify_request(url, signed.headers, _resolver_for(ident))
    assert result.ok, result.reason
    assert result.keyid == ident.keyid


def test_verify_fails_when_authority_differs():
    ident = ephemeral_identity("https://bot.example")
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid, ident.agent_url)
    # Same signature, different target authority -> base changes -> must fail.
    result = verify_request("https://b.example/x", signed.headers, _resolver_for(ident))
    assert not result.ok


def test_verify_fails_on_unknown_key():
    ident = ephemeral_identity("https://bot.example")
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid, ident.agent_url)
    result = verify_request("https://a.example/x", signed.headers, lambda k, a: None)
    assert not result.ok
    assert "resolve" in result.reason


def test_verify_fails_when_expired():
    ident = ephemeral_identity("https://bot.example")
    past = int(time.time()) - 10_000
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid,
                          ident.agent_url, created=past, lifetime=60)
    result = verify_request("https://a.example/x", signed.headers, _resolver_for(ident))
    assert not result.ok
    assert "expired" in result.reason


def test_tampered_signature_is_rejected():
    ident = ephemeral_identity("https://bot.example")
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid, ident.agent_url)
    signed.headers["Signature-Agent"] = '"https://evil.example"'  # alter a covered header
    result = verify_request("https://a.example/x", signed.headers, _resolver_for(ident))
    assert not result.ok


def test_missing_signature_is_unsigned():
    result = verify_request("https://a.example/x", {}, lambda k, a: None)
    assert not result.ok
    assert "unsigned" in result.reason


def test_signature_input_has_web_bot_auth_tag():
    ident = ephemeral_identity("https://bot.example")
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid, ident.agent_url)
    parsed = parse_signature(signed.headers)
    assert parsed.tag == "web-bot-auth"
    assert parsed.keyid == ident.keyid


def test_signature_base_shape():
    base = build_signature_base(
        "example.com", '"https://bot.example"',
        '("@authority" "signature-agent");created=1;expires=2;keyid="k";tag="web-bot-auth"',
    )
    lines = base.split("\n")
    assert lines[0] == '"@authority": example.com'
    assert lines[1] == '"signature-agent": "https://bot.example"'
    assert lines[2].startswith('"@signature-params": (')


def test_keyid_is_stable_thumbprint():
    priv = generate_private_key()
    assert keyid_for(priv.public_key()) == keyid_for(priv.public_key())
