"""RFC 9421 / Web Bot Auth signing + verification round-trips."""
import base64
import time

from wingfoot.keys import ephemeral_identity, generate_private_key, keyid_for
from wingfoot.rfc9421 import (
    COVERED_COMPONENTS,
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


def test_expiry_tolerates_clock_skew_within_max_skew():
    """A signature just past expiry is accepted within max_skew, so a verifier
    whose clock runs slightly fast doesn't reject still-valid signatures."""
    ident = ephemeral_identity("https://bot.example")
    # expires at now-100 (100s ago), well inside the default 300s skew tolerance.
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid,
                          ident.agent_url, created=1_000_000 - 160, lifetime=60)
    result = verify_request("https://a.example/x", signed.headers, _resolver_for(ident),
                            now=1_000_000, max_skew=300)
    assert result.ok, result.reason


def test_expiry_beyond_skew_still_fails():
    ident = ephemeral_identity("https://bot.example")
    # expires at now-400, past the 300s skew tolerance -> must be rejected.
    signed = sign_request("https://a.example/x", ident.private_key, ident.keyid,
                          ident.agent_url, created=1_000_000 - 460, lifetime=60)
    result = verify_request("https://a.example/x", signed.headers, _resolver_for(ident),
                            now=1_000_000, max_skew=300)
    assert not result.ok
    assert "expired" in result.reason


def _sign_without_expires(ident, url, created):
    """Craft a valid signature that omits the `expires` parameter (sign_request
    always sets one, so we build the base by hand)."""
    inner = " ".join(f'"{c}"' for c in COVERED_COMPONENTS)
    params = f'({inner});created={created};keyid="{ident.keyid}";tag="web-bot-auth"'
    sig_agent = f'"{ident.agent_url}"'
    base = build_signature_base(authority_of(url), sig_agent, params)
    sig = ident.private_key.sign(base.encode("utf-8"))
    return {
        "Signature-Agent": sig_agent,
        "Signature-Input": f"sig1={params}",
        "Signature": f"sig1=:{base64.b64encode(sig).decode('ascii')}:",
    }


def test_signature_without_expires_is_rejected():
    """A signature with no `expires` would verify forever (replayable). Web Bot
    Auth requires an expiry, so a missing one must be rejected."""
    ident = ephemeral_identity("https://bot.example")
    url = "https://a.example/x"
    headers = _sign_without_expires(ident, url, created=1_000_000 - 10)
    result = verify_request(url, headers, _resolver_for(ident), now=1_000_000)
    assert not result.ok
    assert "expires" in result.reason
