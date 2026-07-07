"""http.request sends a descriptive User-Agent, not urllib's CDN-blocked default."""
import contextlib

from wingfoot import http as _http


class _FakeResp:
    status = 200
    headers: dict = {}

    def read(self) -> bytes:
        return b"{}"


def _capture_request(monkeypatch) -> dict:
    """Intercept urlopen so we can inspect the outgoing Request without a network."""
    seen: dict = {}

    @contextlib.contextmanager
    def fake_urlopen(req, timeout=None):
        seen["req"] = req
        yield _FakeResp()

    monkeypatch.setattr("wingfoot.http.urllib.request.urlopen", fake_urlopen)
    return seen


def test_default_user_agent_is_identifiable(monkeypatch):
    seen = _capture_request(monkeypatch)
    _http.request("http://example.test/")
    ua = seen["req"].get_header("User-agent")
    # A verified-bot tool must not go out as the blocked "Python-urllib/x.y".
    assert ua is not None
    assert ua.startswith("wingfoot/")
    assert "Python-urllib" not in ua


def test_caller_can_override_user_agent(monkeypatch):
    seen = _capture_request(monkeypatch)
    _http.request("http://example.test/", headers={"User-Agent": "custom/9.9"})
    assert seen["req"].get_header("User-agent") == "custom/9.9"
