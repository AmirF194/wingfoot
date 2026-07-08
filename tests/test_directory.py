"""Key lookup in a JWKS directory (`find_key`)."""
from wingfoot.directory import find_key
from wingfoot.keys import ephemeral_identity


def test_finds_key_by_thumbprint():
    ident = ephemeral_identity("https://bot.example")
    jwks = {"keys": [ident.jwk]}
    assert find_key(jwks, ident.keyid) is not None


def test_finds_key_alongside_non_okp_keys():
    """A directory may publish other key types (RSA/EC) or extra keys during
    rotation. Their presence must not break the lookup — earlier, computing the
    thumbprint of a non-OKP JWK raised KeyError and crashed find_key."""
    ident = ephemeral_identity("https://bot.example")
    jwks = {"keys": [
        {"kty": "RSA", "n": "sXchabc", "e": "AQAB", "kid": "some-rsa-key"},
        {"kty": "EC", "crv": "P-256", "x": "f83OJ", "y": "x_FEz", "kid": "some-ec-key"},
        ident.jwk,
    ]}
    assert find_key(jwks, ident.keyid) is not None


def test_missing_key_returns_none():
    ident = ephemeral_identity("https://bot.example")
    other = ephemeral_identity("https://other.example")
    jwks = {"keys": [other.jwk]}
    assert find_key(jwks, ident.keyid) is None


def test_malformed_entries_are_skipped():
    ident = ephemeral_identity("https://bot.example")
    jwks = {"keys": [None, {}, "not-a-jwk", {"kty": "oct"}, ident.jwk]}
    assert find_key(jwks, ident.keyid) is not None


def test_empty_directory_returns_none():
    ident = ephemeral_identity("https://bot.example")
    assert find_key({"keys": []}, ident.keyid) is None
    assert find_key({}, ident.keyid) is None
