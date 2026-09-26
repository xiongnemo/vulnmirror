import io
import urllib.error

import pytest

from vulnmirror import build, logs, net, update
from vulnmirror.cli import parser


@pytest.fixture(autouse=True)
def quiet_afterwards():
    yield
    logs.setup(0)


def test_verbose_flag_before_or_after_the_subcommand():
    assert parser().parse_args(["update"]).verbose == 0
    assert parser().parse_args(["-vv", "update"]).verbose == 2
    assert parser().parse_args(["update", "-vvv"]).verbose == 3
    assert parser().parse_args(["-v", "sql", "select 1"]).verbose == 1


def test_update_is_quiet_by_default(home, capsys):
    build.build(home, log=lambda *_: None)
    logs.setup(0)
    update.update(home, only=("ghsa",))
    assert capsys.readouterr().err == ""


def test_vv_shows_steps_and_git_commands(home, capsys):
    build.build(home, log=lambda *_: None)
    logs.setup(2)
    update.update(home, only=("ghsa",))
    err = capsys.readouterr().err
    assert "vulnmirror.update: ghsa: starting" in err
    assert "vulnmirror.ghsa: git -C" in err
    assert "vulnmirror.sql" not in err


def test_vvv_traces_sql_statements(home, capsys):
    build.build(home, log=lambda *_: None)
    logs.setup(3)
    update.update(home, only=("ghsa",))
    sql = [line for line in capsys.readouterr().err.splitlines() if " TRACE vulnmirror.sql: " in line]
    assert any("snapshot" in line for line in sql)
    assert all(len(line.split("vulnmirror.sql: ", 1)[1]) <= logs.SQL_MAX_CHARS + 20 for line in sql)


class FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_get_json_logs_request_retry_and_response(monkeypatch, capsys):
    calls = []

    def urlopen(req, timeout, context):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
        return FakeResponse(b'{"ok": true}')

    monkeypatch.setattr(net.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    logs.setup(2)
    assert net.get_json("https://example.invalid/x.json") == {"ok": True}
    err = capsys.readouterr().err
    assert "GET https://example.invalid/x.json -> HTTP 503" in err
    assert "retrying https://example.invalid/x.json in 2s" in err
    assert "(attempt 2/5)" in err
    assert "-> 200, 12 bytes" in err


def test_get_json_is_silent_below_vv(monkeypatch, capsys):
    monkeypatch.setattr(net.urllib.request, "urlopen", lambda req, timeout, context: FakeResponse(b"{}"))
    logs.setup(1)
    net.get_json("https://example.invalid/y.json")
    assert capsys.readouterr().err == ""
