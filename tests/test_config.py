from vulnmirror import config


def isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv(config.ENV_HOME, raising=False)


def test_default_home(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    assert config.resolve_home() == (tmp_path / "data" / "vulnmirror", "default")


def test_resolution_order(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    config.write_config({"home": str(tmp_path / "from-config")})
    home, source = config.resolve_home()
    assert home == (tmp_path / "from-config").resolve() and source.endswith("config.toml")
    monkeypatch.setenv(config.ENV_HOME, str(tmp_path / "from-env"))
    assert config.resolve_home() == ((tmp_path / "from-env").resolve(), "$VULNMIRROR_HOME")
    assert config.resolve_home(str(tmp_path / "from-cli")) == ((tmp_path / "from-cli").resolve(), "--home")


def test_config_roundtrip_escapes(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    tricky = str(tmp_path / 'we"ird\\dir')
    config.write_config({"home": tricky})
    assert config.read_config()["home"] == tricky


def test_expand_user(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert config.expand_path("~/x") == (tmp_path / "x").resolve()
