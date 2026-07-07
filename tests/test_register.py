"""`wingfoot register`: preflight + a ready-to-paste registration packet per provider."""
import json

from wingfoot import DIRECTORY_PATH, WEB_BOT_AUTH_TAG
from wingfoot import http as _http
from wingfoot.directory import directory_json
from wingfoot.keys import ephemeral_identity
from wingfoot.register import PROVIDERS, get_provider, preflight, registration_fields
from wingfoot.rfc9421 import sign_directory

AGENT = "https://fastinfer.org"
DIR_URL = AGENT + DIRECTORY_PATH


def _identity():
    return ephemeral_identity(agent_url=AGENT)


def _serve_directory(monkeypatch, identity, *, status=200, jwks=None, sign=True):
    """Fake the hosted directory: _http.request returns this JWKS, optionally signed."""
    body = (jwks if jwks is not None else directory_json([identity.jwk])).encode()
    headers = sign_directory(DIR_URL, identity.private_key, identity.keyid).headers if sign else {}

    def fake_request(url, **kwargs):
        assert url == DIR_URL
        return _http.Response(status, dict(headers), body)

    monkeypatch.setattr("wingfoot.register._http.request", fake_request)


# --- provider registry ------------------------------------------------------

def test_registry_covers_known_verifiers():
    slugs = [p.slug for p in PROVIDERS]
    assert "cloudflare" in slugs and "datadome" in slugs
    assert len(slugs) == len(set(slugs))
    for p in PROVIDERS:
        assert p.form_url.startswith("https://")


def test_get_provider():
    assert get_provider("datadome").name.startswith("DataDome")
    assert get_provider("nope") is None


# --- registration packet ----------------------------------------------------

def test_fields_contain_what_the_forms_ask_for():
    identity = _identity()
    fields = dict(registration_fields(identity))
    assert fields["Key directory URL"] == DIR_URL
    assert fields["Signature-Agent (domain)"] == AGENT
    assert fields["Key ID (JWK thumbprint)"] == identity.keyid
    assert fields["Request signature tag"] == WEB_BOT_AUTH_TAG
    assert fields["User-Agent"] == _http.DEFAULT_USER_AGENT
    assert "email" in fields["Contact email"]  # placeholder until --email is given


def test_fields_honor_overrides():
    fields = dict(registration_fields(_identity(), email="dev@fastinfer.org", user_agent="mybot/2.0"))
    assert fields["Contact email"] == "dev@fastinfer.org"
    assert fields["User-Agent"] == "mybot/2.0"


# --- preflight --------------------------------------------------------------

def _oks(checks):
    return {title: ok for ok, title, _ in checks}


def test_preflight_all_green_when_directory_is_hosted_and_signed(monkeypatch):
    identity = _identity()
    _serve_directory(monkeypatch, identity)
    assert all(ok for ok, _, _ in preflight(identity))


def test_preflight_flags_missing_key(monkeypatch):
    identity = _identity()
    other = ephemeral_identity(agent_url=AGENT)  # directory hosts a different key
    _serve_directory(monkeypatch, identity, jwks=directory_json([other.jwk]))
    assert _oks(preflight(identity))["Directory publishes this key"] is False


def test_preflight_flags_unsigned_directory(monkeypatch):
    identity = _identity()
    _serve_directory(monkeypatch, identity, sign=False)
    assert _oks(preflight(identity))["Directory response is signed"] is False


def test_preflight_flags_unreachable_directory(monkeypatch):
    identity = _identity()
    _serve_directory(monkeypatch, identity, status=403)
    checks = preflight(identity)
    assert checks[-1][0] is False and "403" in checks[-1][2]


def test_preflight_requires_public_origin():
    identity = ephemeral_identity(agent_url="local-placeholder")
    checks = preflight(identity)
    assert checks[0][0] is False and "wingfoot init" in checks[0][2]


def test_preflight_rejects_non_jwks_body(monkeypatch):
    identity = _identity()
    _serve_directory(monkeypatch, identity, jwks=json.dumps(["not", "a", "jwks"]))
    checks = preflight(identity)
    assert checks[-1][0] is False and "JWKS" in checks[-1][1]
