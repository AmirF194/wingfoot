"""Ed25519 key handling + JWK / JWKS helpers for Web Bot Auth.

The signing key is an Ed25519 private key. The public key is published as a JWK
(kty=OKP, crv=Ed25519) inside a JWKS at the `.well-known` directory. The key id
(`keyid`) is the RFC 7638 JWK thumbprint, so it is stable and self-certifying.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64u(data: bytes) -> str:
    """URL-safe base64 without padding (used inside JWKs)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_jwk(public_key: Ed25519PublicKey) -> dict:
    """Public key as a JWK, including its thumbprint as `kid`."""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
    jwk["kid"] = jwk_thumbprint(jwk)
    jwk["use"] = "sig"
    jwk["alg"] = "EdDSA"
    return jwk


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint over the required OKP members, in lexical order."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u(hashlib.sha256(canonical.encode("utf-8")).digest())


def public_key_from_jwk(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"unsupported JWK: kty={jwk.get('kty')} crv={jwk.get('crv')}")
    return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def keyid_for(public_key: Ed25519PublicKey) -> str:
    return public_jwk(public_key)["kid"]


# ---------------------------------------------------------------------------
# On-disk identity (persisted by `wingfoot init`, loaded by sign/doctor)
# ---------------------------------------------------------------------------

DEFAULT_HOME = Path.home() / ".wingfoot"


class IdentityError(ValueError):
    """A stored identity exists but can't be loaded (corrupt key or config).

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers keep
    working; the CLI catches it to print a clean message instead of a traceback.
    """


@dataclass
class Identity:
    private_key: Ed25519PrivateKey
    agent_url: str  # the origin that hosts this bot's directory

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def keyid(self) -> str:
        return keyid_for(self.public_key)

    @property
    def jwk(self) -> dict:
        return public_jwk(self.public_key)


def save_identity(identity: Identity, home: Path = DEFAULT_HOME) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    key_path = home / "private_key.pem"
    pem = identity.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    (home / "config.json").write_text(
        json.dumps({"agent_url": identity.agent_url, "keyid": identity.keyid}, indent=2)
    )
    return home


def load_identity(home: Path = DEFAULT_HOME) -> Identity | None:
    """Load the persisted identity, or ``None`` if none has been created.

    Raises :class:`IdentityError` (with a re-run hint) when an identity exists but
    is unreadable — a corrupt key file, a truncated/edited ``config.json``, or a
    missing ``agent_url`` — so callers get an actionable message, not a raw
    ``JSONDecodeError``/``KeyError``.
    """
    key_path = home / "private_key.pem"
    config_path = home / "config.json"
    if not key_path.exists() or not config_path.exists():
        return None
    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except ValueError as exc:
        raise IdentityError(f"private key in {home} is unreadable ({exc}); re-run `wingfoot init`") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise IdentityError(f"stored key in {home} is not an Ed25519 private key; re-run `wingfoot init`")
    try:
        config = json.loads(config_path.read_text())
        agent_url = config["agent_url"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise IdentityError(
            f"identity config {config_path} is corrupt or incomplete ({exc}); re-run `wingfoot init`"
        ) from exc
    return Identity(private_key=private_key, agent_url=agent_url)


def ephemeral_identity(agent_url: str) -> Identity:
    """A throwaway identity for demos / doctor when nothing is persisted."""
    return Identity(private_key=generate_private_key(), agent_url=agent_url)
