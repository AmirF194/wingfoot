"""Minimal RFC 9421 (HTTP Message Signatures), Web Bot Auth profile.

Web Bot Auth signs, at minimum, the ``@authority`` derived component and the
``signature-agent`` header, with the fixed parameter ``tag="web-bot-auth"``. The
signature is Ed25519 over the RFC 9421 "signature base".

This module implements that slice: enough to interoperate, small enough to read.
References: RFC 9421 §2.3 (base), §2.2.3 (@authority), and the Web Bot Auth architecture draft.
"""
from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import WEB_BOT_AUTH_TAG

# The covered components for a Web Bot Auth signature, in signing order.
COVERED_COMPONENTS = ("@authority", "signature-agent")
DEFAULT_LABEL = "sig1"
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def authority_of(url: str) -> str:
    """The RFC 9421 ``@authority`` value: lowercase host, port only if non-default."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(parts.scheme) != port:
        return f"{host}:{port}"
    return host


def signature_agent_field(agent_url: str) -> str:
    """The ``Signature-Agent`` header value, a Structured-Fields string (quoted)."""
    return f'"{agent_url}"'


def _params_value(created: int, expires: int, keyid: str) -> str:
    """The serialized ``@signature-params`` value (also the Signature-Input body)."""
    inner = " ".join(f'"{c}"' for c in COVERED_COMPONENTS)
    return (
        f"({inner});created={created};expires={expires}"
        f';keyid="{keyid}";tag="{WEB_BOT_AUTH_TAG}"'
    )


def build_signature_base(authority: str, sig_agent_field: str, params_value: str) -> str:
    """Reconstruct the exact bytes that get signed, per RFC 9421 §2.5."""
    lines = [
        f'"@authority": {authority}',
        f'"signature-agent": {sig_agent_field}',
        f'"@signature-params": {params_value}',
    ]
    return "\n".join(lines)


@dataclass
class SignedHeaders:
    headers: dict
    signature_base: str
    keyid: str
    created: int
    expires: int


def sign_request(
    url: str,
    private_key,
    keyid: str,
    agent_url: str,
    *,
    created: Optional[int] = None,
    lifetime: int = 300,
    label: str = DEFAULT_LABEL,
) -> SignedHeaders:
    """Produce the Signature-Agent / Signature-Input / Signature headers for a request."""
    created = int(created if created is not None else time.time())
    expires = created + lifetime
    sig_agent = signature_agent_field(agent_url)
    params_value = _params_value(created, expires, keyid)
    base = build_signature_base(authority_of(url), sig_agent, params_value)
    signature = private_key.sign(base.encode("utf-8"))
    headers = {
        "Signature-Agent": sig_agent,
        "Signature-Input": f"{label}={params_value}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode('ascii')}:",
    }
    return SignedHeaders(headers, base, keyid, created, expires)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

_PARAM_RE = {
    "created": re.compile(r"created=(\d+)"),
    "expires": re.compile(r"expires=(\d+)"),
    "keyid": re.compile(r'keyid="([^"]+)"'),
    "tag": re.compile(r'tag="([^"]+)"'),
}


@dataclass
class ParsedSignature:
    label: str
    params_value: str
    created: Optional[int]
    expires: Optional[int]
    keyid: Optional[str]
    tag: Optional[str]
    signature: bytes


def _get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def parse_signature(headers: Mapping[str, str]) -> ParsedSignature:
    sig_input = _get(headers, "Signature-Input")
    sig = _get(headers, "Signature")
    if not sig_input or not sig:
        raise ValueError("missing Signature-Input or Signature header")
    label, _, params_value = sig_input.partition("=")
    label = label.strip()
    params_value = params_value.strip()
    if not params_value.startswith("("):
        raise ValueError("malformed Signature-Input (expected component list)")

    def _int(name):
        m = _PARAM_RE[name].search(params_value)
        return int(m.group(1)) if m else None

    def _str(name):
        m = _PARAM_RE[name].search(params_value)
        return m.group(1) if m else None

    # Signature value: <label>=:<base64>:
    m = re.search(rf"{re.escape(label)}=:([^:]+):", sig)
    if not m:
        raise ValueError("malformed Signature header")
    signature = base64.b64decode(m.group(1))

    return ParsedSignature(
        label=label,
        params_value=params_value,
        created=_int("created"),
        expires=_int("expires"),
        keyid=_str("keyid"),
        tag=_str("tag"),
        signature=signature,
    )


@dataclass
class VerifyResult:
    ok: bool
    reason: str = ""
    keyid: Optional[str] = None
    checks: list = field(default_factory=list)  # (name, ok, detail)


# resolver(keyid, agent_url) -> Ed25519PublicKey | None
KeyResolver = Callable[[str, Optional[str]], Optional[Ed25519PublicKey]]


def verify_request(
    url: str,
    headers: Mapping[str, str],
    resolve_key: KeyResolver,
    *,
    now: Optional[int] = None,
    max_skew: int = 300,
) -> VerifyResult:
    """Verify a Web Bot Auth signature on a request. Returns a structured result."""
    now = int(now if now is not None else time.time())
    checks: list = []

    try:
        parsed = parse_signature(headers)
    except ValueError as exc:
        return VerifyResult(False, f"unsigned or malformed: {exc}", checks=checks)

    def add(name, ok, detail=""):
        checks.append((name, ok, detail))
        return ok

    add("signature headers present", True)

    if parsed.tag != WEB_BOT_AUTH_TAG:
        add("tag is web-bot-auth", False, f"got tag={parsed.tag!r}")
        return VerifyResult(False, f'tag must be "{WEB_BOT_AUTH_TAG}", got {parsed.tag!r}',
                            keyid=parsed.keyid, checks=checks)
    add("tag is web-bot-auth", True)

    if parsed.expires is not None and now > parsed.expires:
        add("signature not expired", False, f"expired {now - parsed.expires}s ago")
        return VerifyResult(False, f"signature expired {now - parsed.expires}s ago",
                            keyid=parsed.keyid, checks=checks)
    add("signature not expired", True)

    if parsed.created is not None and parsed.created > now + max_skew:
        add("created timestamp sane", False, f"{parsed.created - now}s in the future")
        return VerifyResult(False, "created timestamp is in the future (clock skew?)",
                            keyid=parsed.keyid, checks=checks)
    add("created timestamp sane", True)

    if not parsed.keyid:
        add("keyid present", False)
        return VerifyResult(False, "no keyid in signature", checks=checks)
    add("keyid present", True, parsed.keyid)

    agent = _get(headers, "Signature-Agent")
    agent_url = agent.strip('"') if agent else None
    public_key = resolve_key(parsed.keyid, agent_url)
    if public_key is None:
        add("public key resolved from directory", False, f"keyid={parsed.keyid}")
        return VerifyResult(False, "could not resolve public key from the directory",
                            keyid=parsed.keyid, checks=checks)
    add("public key resolved from directory", True)

    if agent is None:
        add("signature-agent header present", False)
        return VerifyResult(False, "missing Signature-Agent header", keyid=parsed.keyid, checks=checks)

    base = build_signature_base(authority_of(url), agent, parsed.params_value)
    try:
        public_key.verify(parsed.signature, base.encode("utf-8"))
    except InvalidSignature:
        add("cryptographic signature valid", False, "Ed25519 verification failed")
        return VerifyResult(False, "signature did not verify (wrong key or altered request)",
                            keyid=parsed.keyid, checks=checks)
    add("cryptographic signature valid", True)

    return VerifyResult(True, "verified", keyid=parsed.keyid, checks=checks)
