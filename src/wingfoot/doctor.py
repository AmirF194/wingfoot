"""wingfoot doctor <url>: send a signed request and report whether it worked and why."""
from __future__ import annotations

from typing import Optional

from . import http as _http
from .directory import directory_url_for, find_key
from .keys import DEFAULT_HOME, ephemeral_identity, load_identity
from .rfc9421 import sign_request, verify_directory, verify_request
from .verifier import _Colors


def _check(C, ok: Optional[bool], title: str, detail: str = "") -> None:
    if ok is True:
        mark = f"{C.green}ok  {C.reset}"
    elif ok is False:
        mark = f"{C.red}FAIL{C.reset}"
    else:
        mark = f"{C.dim}-   {C.reset}"
    line = f"  {mark} {title}"
    if detail:
        line += f"\n         {C.dim}{detail}{C.reset}"
    print(line)


def doctor(url: str, home=DEFAULT_HOME) -> int:
    C = _Colors()
    identity = load_identity(home)
    ephemeral = identity is None
    if identity is None:
        identity = ephemeral_identity(agent_url=_origin(url))

    print(f"{C.bold}wingfoot doctor{C.reset} {C.dim}{url}{C.reset}\n")

    # 1. Identity
    if ephemeral:
        _check(C, None, "Bot identity",
               "using a throwaway key (run `wingfoot init` to create a lasting one)")
    else:
        _check(C, True, "Bot identity",
               f"keyid {identity.keyid[:16]}...  directory at {identity.agent_url}")

    # 2. Local signature self-test
    signed = sign_request(url, identity.private_key, identity.keyid, identity.agent_url)
    self_result = verify_request(
        url, signed.headers,
        resolve_key=lambda kid, agent: identity.public_key if kid == identity.keyid else None,
    )
    _check(C, self_result.ok, "Signature is well-formed and cryptographically valid",
           self_result.reason if not self_result.ok else "signing is correct per RFC 9421")

    # 3. Directory reachability + the directory's own signature
    dir_ok: Optional[bool] = None
    if identity.agent_url.startswith("http"):
        dir_url = directory_url_for(identity.agent_url)
        try:
            resp = _http.request(dir_url)
            if resp.status != 200:
                raise OSError(f"returned HTTP {resp.status}")
            jwks = resp.json()
            if not isinstance(jwks, dict):
                raise ValueError("did not return a JWKS document")
            found = find_key(jwks, identity.keyid) is not None
            dir_ok = found
            _check(C, found, "Key directory reachable and publishes this key",
                   dir_url if found else f"reachable, but your keyid is not listed at {dir_url}")
            # The directory response must carry its own signature (draft §5.2);
            # verifiers such as Cloudflare reject an unsigned directory.
            dsig = verify_directory(dir_url, resp.headers,
                                    resolve_key=lambda kid, agent: find_key(jwks, kid))
            _check(C, dsig.ok, "Directory response is signed",
                   "verifiers can trust it" if dsig.ok
                   else f"{dsig.reason}. Run `wingfoot directory --sign` and serve those headers.")
        except Exception as exc:
            dir_ok = False
            _check(C, False, "Key directory reachable",
                   f"{dir_url}: {exc}. A verifier cannot fetch your public key. "
                   f"Host that JSON (see `wingfoot directory`) or run `wingfoot serve`.")
    else:
        _check(C, None, "Key directory",
               "no public directory URL set, so verifiers cannot fetch your key until you host one")

    # 4. Live probe
    print(f"\n{C.bold}Probing the target{C.reset}")
    unsigned = _safe_request(url)
    signed_resp = _safe_request(url, headers=signed.headers)
    if unsigned is None or signed_resp is None:
        _check(C, False, "Reachable over HTTP", "could not connect to the target")
        print(f"\n{C.red}Could not reach the target.{C.reset}")
        return 1

    _check(C, None, "Unsigned request", f"HTTP {unsigned.status}")
    got_in = 200 <= signed_resp.status < 300
    _check(C, got_in, "Signed request", f"HTTP {signed_resp.status}")

    # 5. Verdict
    print()
    if got_in and unsigned.status != signed_resp.status:
        print(f"{C.green}Verified-bot access is working: signing changed "
              f"HTTP {unsigned.status} to {signed_resp.status}.{C.reset}")
        return 0
    if got_in:
        print(f"{C.green}The target accepted the request.{C.reset} "
              f"{C.dim}(It also served the unsigned request, so it may not require auth.){C.reset}")
        return 0

    reason = _remote_reason(signed_resp)
    if reason:
        print(f"{C.red}The target rejected your signed request.{C.reset}")
        print(f"  {C.bold}Reason from the verifier:{C.reset} {reason}")
        print(f"  {C.dim}This is a fixable config issue on your side. See the failed check above.{C.reset}")
    elif self_result.ok and dir_ok:
        print(f"{C.yellow}Your signature is valid and your key is published, but "
              f"{_origin(url)} still returned {signed_resp.status}.{C.reset}")
        print(f"  {C.dim}Most likely the target does not support Web Bot Auth yet, or has not "
              f"allow-listed your key. Next: run `wingfoot register` for a ready-to-paste "
              f"registration packet for each verifier program.{C.reset}")
    else:
        print(f"{C.red}Blocked, and your local setup has a problem above. Fix that first.{C.reset}")
    return 1


def _safe_request(url, headers=None):
    try:
        return _http.request(url, headers=headers or {})
    except Exception:
        return None


def _remote_reason(resp) -> Optional[str]:
    data = resp.json()
    if isinstance(data, dict) and data.get("verified") is False:
        return data.get("reason")
    return None


def _origin(url: str) -> str:
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
