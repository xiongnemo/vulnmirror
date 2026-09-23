import json

from vulnmirror import cli, config


def test_cli_build_status_sql_filter(home, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    base = ["--home", str(home.home)]
    assert cli.main([*base, "build"]) == 0
    assert cli.main([*base, "status"]) == 0
    assert "rows cve" in capsys.readouterr().out
    assert cli.main([*base, "sql", "SELECT id, state FROM cve ORDER BY id", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{"id": "CVE-2099-0001", "state": "PUBLISHED"}, {"id": "CVE-2099-0002", "state": "REJECTED"}]
    assert cli.main([*base, "filter", "--vendor", "examplevendor", "--count"]) == 0
    assert capsys.readouterr().out.strip() == "1"
    out_csv = tmp_path / "hits.csv"
    assert (
        cli.main([*base, "filter", "--cpe-part", "h", "--cpe-scope", "any", "--format", "csv", "-o", str(out_csv)]) == 0
    )
    assert out_csv.read_text().splitlines()[0].startswith("cve_id,")


def test_cli_config_set_home(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv(config.ENV_HOME, raising=False)
    assert cli.main(["config", "set-home", str(tmp_path / "mirror")]) == 0
    assert cli.main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert str((tmp_path / "mirror").resolve()) in out and "config.toml" in out


def test_cli_missing_database_is_a_clean_error(capsys, tmp_path):
    assert cli.main(["--home", str(tmp_path / "empty"), "status"]) == 2
    assert "run `vulnmirror build` first" in capsys.readouterr().err


def test_cli_get_rejects_bad_refs(capsys, tmp_path):
    assert cli.main(["--home", str(tmp_path), "get", "not-an-id"]) == 1
    assert "skip:" in capsys.readouterr().err
