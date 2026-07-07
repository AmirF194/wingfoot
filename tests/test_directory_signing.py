"""Signing the key directory response (RFC 9421 directory draft §5.2).

The headline test verifies Cloudflare's OWN live directory signature with
wingfoot's base construction — if that passes, a directory wingfoot signs the
same way will pass Cloudflare's validator.
"""
from wingfoot import DIRECTORY_TAG
from wingfoot.keys import ephemeral_identity, public_key_from_jwk
from wingfoot.rfc9421 import sign_directory, verify_directory

DIR_URL = "https://fastinfer.org/.well-known/http-message-signatures-directory"


def _resolver(identity):
    return lambda keyid, agent: identity.public_key if keyid == identity.keyid else None


def test_sign_then_verify_round_trip():
    ident = ephemeral_identity(agent_url="https://fastinfer.org")
    signed = sign_directory(DIR_URL, ident.private_key, ident.keyid)
    result = verify_directory(DIR_URL, signed.headers, _resolver(ident))
    assert result.ok, result.reason


def test_signature_input_matches_cloudflare_profile():
    ident = ephemeral_identity(agent_url="https://fastinfer.org")
    signed = sign_directory(DIR_URL, ident.private_key, ident.keyid, created=1000, lifetime=300)
    si = signed.headers["Signature-Input"]
    # Exact shape Cloudflare's tooling emits and validates.
    assert si == (
        f'binding0=("@authority";req);created=1000;keyid="{ident.keyid}"'
        f';alg="ed25519";expires=1300;tag="http-message-signatures-directory"'
    )
    assert signed.headers["Signature"].startswith("binding0=:")


def test_wrong_authority_fails():
    """A mirror served under a different host cannot reuse the signature."""
    ident = ephemeral_identity(agent_url="https://fastinfer.org")
    signed = sign_directory(DIR_URL, ident.private_key, ident.keyid)
    other = "https://evil.example/.well-known/http-message-signatures-directory"
    assert not verify_directory(other, signed.headers, _resolver(ident)).ok


def test_expired_signature_fails():
    ident = ephemeral_identity(agent_url="https://fastinfer.org")
    signed = sign_directory(DIR_URL, ident.private_key, ident.keyid, created=1000, lifetime=300)
    assert not verify_directory(DIR_URL, signed.headers, _resolver(ident), now=2000).ok


def test_verifies_cloudflares_live_directory():
    """Byte-exact regression: wingfoot verifies Cloudflare's real signed directory.

    Captured live from Cloudflare's reference server. If the signature base ever
    drifts from Cloudflare's, this fails.
    """
    authority = "http-message-signatures-example.research.cloudflare.com"
    cf_url = f"https://{authority}/.well-known/http-message-signatures-directory"
    headers = {
        "Signature-Input": (
            'binding0=("@authority";req);created=1783129585;'
            'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";'
            'alg="ed25519";expires=1783129885;tag="http-message-signatures-directory"'
        ),
        "Signature": (
            "binding0=:iZqb53u8rp81QldASkp9mPZei2Syaw6dfGYTmfV0wISvd0cE"
            "+rtywzNybtXJ+itYniK3rcCcCxQAZt4lcw4sBA==:"
        ),
    }
    cf_pubkey = public_key_from_jwk({
        "kty": "OKP", "crv": "Ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    })
    result = verify_directory(
        cf_url, headers,
        resolve_key=lambda keyid, agent: cf_pubkey,
        now=1783129700,  # within Cloudflare's created..expires window
    )
    assert result.ok, result.reason
    assert result.keyid == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def test_directory_tag_constant():
    assert DIRECTORY_TAG == "http-message-signatures-directory"
