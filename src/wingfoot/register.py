"""wingfoot register: a ready-to-paste registration packet for verifier programs.

No verifier offers one-click registration yet: Cloudflare, DataDome, and the
rest each run their own web form with a human review behind it. This command
shrinks that manual step to copy/paste — it re-checks your setup the way a
reviewer would, then prints exactly what to enter into each form.
"""
from __future__ import annotations

import webbrowser
from dataclasses import dataclass
from typing import Optional

from . import WEB_BOT_AUTH_TAG
from . import http as _http
from .directory import directory_url_for, find_key
from .doctor import _check
from .keys import Identity
from .rfc9421 import verify_directory
from .verifier import _Colors


@dataclass(frozen=True)
class Provider:
    slug: str
    name: str
    form_url: str
    how: str  # where the form lives and what happens after submitting


PROVIDERS = (
    Provider(
        slug="cloudflare",
        name="Cloudflare — Verified Bots",
        form_url="https://dash.cloudflare.com/?to=/:account/configurations",
        how='Log in, then Manage Account > Configurations > Bot Submission Form. '
            'Pick verification method "Request Signature".',
    ),
    Provider(
        slug="datadome",
        name="DataDome — Bot & AI Agent Verification",
        form_url="https://datadome.co/resources/bot-and-ai-agent-verification/",
        how="Public form; their analysts review it and add you to the verified-bot catalog.",
    ),
)


def get_provider(slug: str) -> Optional[Provider]:
    return next((p for p in PROVIDERS if p.slug == slug), None)


def registration_fields(identity: Identity, *, email: str | None = None,
                        user_agent: str | None = None) -> list[tuple[str, str]]:
    """The answers every provider form asks for, in copy/paste order."""
    return [
        ("Bot / agent name", _host(identity.agent_url)),
        ("User-Agent", user_agent or _http.DEFAULT_USER_AGENT),
        ("Signature-Agent (domain)", identity.agent_url),
        ("Key directory URL", directory_url_for(identity.agent_url)),
        ("Key ID (JWK thumbprint)", identity.keyid),
        ("Key type / algorithm", "Ed25519 (EdDSA)"),
        ("Request signature tag", WEB_BOT_AUTH_TAG),
        ("Contact email", email or "<your contact email>"),
    ]


def preflight(identity: Identity) -> list[tuple[Optional[bool], str, str]]:
    """The checks a reviewer's tooling runs against your directory, as (ok, title, detail)."""
    checks: list[tuple[Optional[bool], str, str]] = []
    if not identity.agent_url.startswith("http"):
        checks.append((False, "Public directory URL",
                       "no public origin set — re-run `wingfoot init --agent https://your-domain`"))
        return checks
    dir_url = directory_url_for(identity.agent_url)
    try:
        resp = _http.request(dir_url)
    except Exception as exc:
        checks.append((False, "Key directory reachable", f"{dir_url}: {exc}"))
        return checks
    if resp.status != 200:
        checks.append((False, "Key directory reachable", f"{dir_url} returned HTTP {resp.status}"))
        return checks
    jwks = resp.json()
    if not isinstance(jwks, dict):
        checks.append((False, "Key directory serves a JWKS", f"{dir_url} did not return a JSON key set"))
        return checks
    checks.append((True, "Key directory reachable", dir_url))

    found = find_key(jwks, identity.keyid) is not None
    checks.append((found, "Directory publishes this key",
                   f"keyid {identity.keyid[:16]}..." if found
                   else "your keyid is not in the hosted JWKS — re-host `wingfoot directory` output"))

    dsig = verify_directory(dir_url, resp.headers,
                            resolve_key=lambda kid, agent: find_key(jwks, kid))
    checks.append((dsig.ok, "Directory response is signed",
                   "reviewers can verify you own it" if dsig.ok
                   else f"{dsig.reason} — run `wingfoot directory --sign` and serve those headers"))
    return checks


def register(identity: Identity, provider_slug: str | None = None, *,
             email: str | None = None, user_agent: str | None = None,
             open_browser: bool = False, skip_checks: bool = False) -> int:
    C = _Colors()
    providers = [p for p in PROVIDERS if provider_slug in (None, p.slug)]

    print(f"{C.bold}wingfoot register{C.reset}\n")
    print(f"{C.dim}No verifier offers automated registration yet: each runs its own form with a "
          f"human review behind it. Below is everything the forms ask for, ready to paste.{C.reset}\n")

    ok = True
    if not skip_checks:
        print(f"{C.bold}Preflight — what a reviewer will check{C.reset}")
        for check_ok, title, detail in preflight(identity):
            _check(C, check_ok, title, detail)
            ok = ok and check_ok is not False
        print()
        if not ok:
            print(f"{C.red}Fix the failed checks before submitting{C.reset} — a reviewer fetching "
                  f"your directory would hit the same problem.\n")

    fields = registration_fields(identity, email=email, user_agent=user_agent)
    width = max(len(k) for k, _ in fields)
    for p in providers:
        print(f"{C.bold}{p.name}{C.reset}")
        print(f"  form   {p.form_url}")
        print(f"  {C.dim}{p.how}{C.reset}")
        for k, v in fields:
            print(f"    {k.ljust(width)}  {v}")
        print()

    if open_browser:
        for p in providers:
            webbrowser.open(p.form_url)

    print(f"{C.dim}Approval is manual and can take days. Once approved, run "
          f"`wingfoot doctor <blocked-url>` again — the 403 should become 200.{C.reset}")
    return 0 if ok else 1


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).netloc or url
