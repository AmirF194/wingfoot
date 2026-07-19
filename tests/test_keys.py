"""Loading and persisting the on-disk identity."""
import pytest

from wingfoot.cli import main
from wingfoot.keys import (
    Identity,
    IdentityError,
    generate_private_key,
    load_identity,
    save_identity,
)


def _make_identity(home):
    ident = Identity(private_key=generate_private_key(), agent_url="https://bot.example")
    save_identity(ident, home)
    return ident


def test_load_identity_none_when_absent(tmp_path):
    assert load_identity(tmp_path) is None


def test_save_then_load_roundtrip(tmp_path):
    saved = _make_identity(tmp_path)
    loaded = load_identity(tmp_path)
    assert loaded is not None
    assert loaded.agent_url == "https://bot.example"
    assert loaded.keyid == saved.keyid


def test_corrupt_config_raises_identity_error(tmp_path):
    _make_identity(tmp_path)
    (tmp_path / "config.json").write_text('{ "keyid": "abc"')  # truncated JSON
    with pytest.raises(IdentityError) as exc:
        load_identity(tmp_path)
    assert "wingfoot init" in str(exc.value)


def test_config_missing_agent_url_raises_identity_error(tmp_path):
    _make_identity(tmp_path)
    (tmp_path / "config.json").write_text('{"keyid": "abc"}')  # valid JSON, no agent_url
    with pytest.raises(IdentityError):
        load_identity(tmp_path)


def test_cli_reports_corrupt_identity_cleanly(tmp_path, monkeypatch, capsys):
    """A corrupt identity should exit 2 with a clean message, not a traceback."""
    _make_identity(tmp_path)
    (tmp_path / "config.json").write_text("not json")
    # `directory` loads the default-home identity; point loading at our tmp home.
    monkeypatch.setattr("wingfoot.cli.load_identity", lambda *a, **k: load_identity(tmp_path))
    rc = main(["directory"])
    assert rc == 2
    assert "wingfoot:" in capsys.readouterr().err
