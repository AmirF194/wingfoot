"""Bare `wingfoot` greets with the full help instead of an argparse error."""
import urllib.error

import pytest

from wingfoot.cli import main


def test_no_args_prints_full_help_and_exits_zero(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: wingfoot" in out
    for command in ("demo", "init", "doctor", "register"):
        assert command in out


def test_unknown_command_still_errors():
    with pytest.raises(SystemExit) as exc:
        main(["not-a-command"])
    assert exc.value.code == 2


def test_sign_reports_connection_error_cleanly(monkeypatch, capsys):
    """`wingfoot sign <unreachable>` should print a clean error and exit 1,
    not surface a urllib traceback to the user."""
    def boom(*args, **kwargs):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr("wingfoot.cli._http.request", boom)
    rc = main(["sign", "http://127.0.0.1:1/"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Could not reach http://127.0.0.1:1/" in err
    assert "Connection refused" in err


def test_sign_print_only_needs_no_network(monkeypatch):
    """--print-only must never touch the network."""
    def boom(*args, **kwargs):
        raise AssertionError("network should not be used with --print-only")

    monkeypatch.setattr("wingfoot.cli._http.request", boom)
    assert main(["sign", "https://example.com/", "--print-only"]) == 0
