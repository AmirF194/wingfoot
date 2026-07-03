"""Drop-in Web Bot Auth signing for the HTTP clients people already use.

Signing becomes one line: hand a wingfoot auth object to `requests` or `httpx` and
every outbound request carries a valid Web Bot Auth signature.

    import requests, wingfoot
    requests.get("https://example.com/", auth=wingfoot.requests_auth())

    import httpx, wingfoot
    httpx.get("https://example.com/", auth=wingfoot.httpx_auth())

These integrations are optional: wingfoot itself needs only `cryptography`. `requests`
and `httpx` are imported lazily, so importing this module never pulls them in.

By default the identity created by `wingfoot init` is used. Pass `identity=` to sign
with a specific one (e.g. `wingfoot.keys.ephemeral_identity(url)` in tests).
"""
from __future__ import annotations

from typing import Optional

from .keys import Identity, load_identity
from .rfc9421 import sign_request


def _resolve_identity(identity: Optional[Identity]) -> Identity:
    if identity is not None:
        return identity
    loaded = load_identity()
    if loaded is None:
        raise RuntimeError(
            "no wingfoot identity found — run `wingfoot init --agent <url>` first, "
            "or pass identity=... explicitly."
        )
    return loaded


def signed_headers(url: str, identity: Optional[Identity] = None, **sign_kwargs) -> dict:
    """The Web Bot Auth headers for a request to `url`, as a plain dict.

    Use this when you drive an HTTP client we don't ship an adapter for — merge the
    returned headers into your request yourself.
    """
    ident = _resolve_identity(identity)
    return dict(
        sign_request(url, ident.private_key, ident.keyid, ident.agent_url, **sign_kwargs).headers
    )


class requests_auth:  # noqa: N801 - reads as a factory at the call site
    """A `requests`-compatible auth callable. `requests.get(url, auth=requests_auth())`.

    Signs per-request, so a long-lived session re-signs each call and never sends an
    expired signature.
    """

    def __init__(self, identity: Optional[Identity] = None, **sign_kwargs):
        self._identity = identity
        self._sign_kwargs = sign_kwargs

    def __call__(self, request):  # requests passes a PreparedRequest
        request.headers.update(signed_headers(request.url, self._identity, **self._sign_kwargs))
        return request


def httpx_auth(identity: Optional[Identity] = None, **sign_kwargs):
    """An `httpx`-compatible auth object. `httpx.get(url, auth=httpx_auth())`.

    Returns an instance of a subclass of `httpx.Auth`; `httpx` is imported here so it
    stays an optional dependency.
    """
    import httpx

    class _WingfootAuth(httpx.Auth):
        def auth_flow(self, request):
            for name, value in signed_headers(str(request.url), identity, **sign_kwargs).items():
                request.headers[name] = value
            yield request

    return _WingfootAuth()
