"""Where vulnmirror keeps its data (the "home" directory).

Resolution order, first match wins:
  1. --home PATH on the command line
  2. $VULNMIRROR_HOME
  3. `home = "..."` in $XDG_CONFIG_HOME/vulnmirror/config.toml (default ~/.config/vulnmirror/config.toml)
  4. $XDG_DATA_HOME/vulnmirror (default ~/.local/share/vulnmirror)
"""

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "VULNMIRROR_HOME"


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "vulnmirror" / "config.toml"


def default_home() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "vulnmirror"


def read_config() -> dict:
    p = config_path()
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def write_config(cfg: dict) -> Path:
    """Write a flat table of string values (the only shape vulnmirror needs)."""
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# vulnmirror configuration"]
    for k, v in cfg.items():
        escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{k} = "{escaped}"')
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def expand_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p))).resolve()


def resolve_home(cli_home: str | None = None) -> tuple[Path, str]:
    """Return (home directory, where the setting came from)."""
    if cli_home:
        return expand_path(cli_home), "--home"
    if os.environ.get(ENV_HOME):
        return expand_path(os.environ[ENV_HOME]), f"${ENV_HOME}"
    home = read_config().get("home")
    if home:
        return expand_path(home), str(config_path())
    return default_home(), "default"


@dataclass(frozen=True)
class Paths:
    """Every file vulnmirror reads or writes, relative to one home directory."""

    home: Path

    @property
    def db(self) -> Path:
        return self.home / "vulnmirror.sqlite"

    @property
    def manifest(self) -> Path:
        return self.home / "MANIFEST.json"

    @property
    def raw(self) -> Path:
        return self.home / "raw"

    @property
    def cvelist_dir(self) -> Path:
        return self.raw / "cvelistV5"

    @property
    def nvd_dir(self) -> Path:
        return self.raw / "nvd"

    @property
    def kev_file(self) -> Path:
        return self.raw / "kev" / "known_exploited_vulnerabilities.json"

    @property
    def ghsa_repo(self) -> Path:
        return self.raw / "ghsa" / "advisory-database"
