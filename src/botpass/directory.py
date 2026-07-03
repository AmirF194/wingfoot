"""The Web Bot Auth key directory: a JWKS served at a well-known path.

A verifier fetches ``<Signature-Agent>/.well-known/http-message-signatures-directory``,
reads this JWKS, and looks up the signer's public key by ``keyid`` (the JWK thumbprint).
"""
from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlsplit

from . import DIRECTORY_PATH
from .keys import jwk_thumbprint, public_key_from_jwk


def build_directory(jwks: list[dict]) -> dict:
    """A JWKS document: {"keys": [ ...public JWKs... ]}."""
    return {"keys": jwks}


def directory_json(jwks: list[dict]) -> str:
    return json.dumps(build_directory(jwks), indent=2)


def directory_url_for(agent_url: str) -> str:
    """Resolve the directory URL from a Signature-Agent value (origin or full URL)."""
    agent_url = agent_url.strip().strip('"').rstrip("/")
    if agent_url.endswith(DIRECTORY_PATH.lstrip("/")):
        return agent_url
    parts = urlsplit(agent_url)
    if parts.path and parts.path != "/":
        # Signature-Agent already points somewhere specific; append the well-known path.
        return agent_url + DIRECTORY_PATH
    return f"{parts.scheme}://{parts.netloc}{DIRECTORY_PATH}"


def find_key(jwks_doc: dict, keyid: str) -> Optional[object]:
    """Return the Ed25519 public key for ``keyid`` from a JWKS, or None."""
    for jwk in jwks_doc.get("keys", []):
        if jwk.get("kid") == keyid or jwk_thumbprint(jwk) == keyid:
            try:
                return public_key_from_jwk(jwk)
            except ValueError:
                continue
    return None
