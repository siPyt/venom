"""Settings: defaults, platform directories, and TOML configuration loading."""

from __future__ import annotations

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import platformdirs

APP_NAME = "venom"
KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

FEED_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*$", re.IGNORECASE)
_SIZE_UNITS = {"": 1, "k": KiB, "m": MiB, "g": GiB, "t": 1024 * GiB}


class ConfigError(Exception):
    pass


def parse_size(value: int | str) -> int:
    """Parse sizes such as ``1048576``, ``"512K"``, ``"256M"`` or ``"2GiB"``."""
    if isinstance(value, bool):
        raise ConfigError(f"invalid size: {value!r}")
    if isinstance(value, int):
        if value < 0:
            raise ConfigError(f"size must not be negative: {value}")
        return value
    match = _SIZE_RE.match(str(value))
    if not match:
        raise ConfigError(f"invalid size: {value!r} (examples: 1048576, 512K, 256M, 2G)")
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2).lower()])


def format_size(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(num) < 1024 or unit == "GiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TiB"


@dataclass
class Limits:
    max_file_size: int = 256 * MiB
    """Files larger than this are reported as not scanned. 0 disables the limit."""
    max_archive_depth: int = 3
    max_archive_members: int = 10_000
    max_member_size: int = 64 * MiB
    max_archive_total: int = 512 * MiB
    """Total decompressed bytes inspected per top-level archive."""
    max_compression_ratio: int = 250
    yara_timeout: int = 60


@dataclass
class ClamAVConfig:
    mode: str = "auto"
    """``auto`` (clamd, then clamscan), ``clamd``, ``clamscan``, or ``off``."""
    clamd_socket: str | None = None
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_timeout: float = 120.0
    clamscan: str | None = None
    freshclam: str | None = None
    database: str | None = None
    """Optional database file or directory passed to clamscan with ``-d``."""


@dataclass
class FeedConfig:
    name: str
    url: str
    sha256: str | None = None
    signature_url: str | None = None
    public_key: str | None = None
    """Base64-encoded raw Ed25519 public key. When set, bundles must be signed."""
    enabled: bool = True
    max_size: int = 128 * MiB


DEFAULT_FEEDS = (
    FeedConfig(
        name="yara-forge-core",
        url="https://github.com/YARAHQ/yara-forge/releases/latest/download/"
        "yara-forge-rules-core.zip",
    ),
)


def _default_excludes() -> list[str]:
    if sys.platform.startswith("linux"):
        return ["/proc", "/sys", "/dev", "/run"]
    if sys.platform == "darwin":
        return ["/dev", "/System/Volumes/Data", "/Volumes/*/.Spotlight-V100"]
    return []


@dataclass
class Settings:
    config_path: Path
    data_dir: Path
    rules_dir: Path
    limits: Limits = field(default_factory=Limits)
    clamav: ClamAVConfig = field(default_factory=ClamAVConfig)
    feeds: list[FeedConfig] = field(default_factory=lambda: list(DEFAULT_FEEDS))
    exclude: list[str] = field(default_factory=_default_excludes)
    workers: int = field(default_factory=lambda: max(1, min(4, os.cpu_count() or 1)))
    follow_symlinks: bool = False
    include_offline: bool = False
    scan_archives: bool = True

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def feeds_dir(self) -> Path:
        return self.data_dir / "feeds"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    def feed(self, name: str) -> FeedConfig:
        for feed in self.feeds:
            if feed.name == name:
                return feed
        raise ConfigError(f"unknown feed: {name!r}")


def default_paths() -> tuple[Path, Path]:
    """Return ``(config_dir, data_dir)``. ``VENOM_HOME`` makes both a single portable directory."""
    home = os.environ.get("VENOM_HOME")
    if home:
        root = Path(home).expanduser().resolve()
        return root, root
    config_dir = Path(platformdirs.user_config_dir(APP_NAME, appauthor=False))
    data_dir = Path(platformdirs.user_data_dir(APP_NAME, appauthor=False))
    return config_dir, data_dir


def _build(cls: type, raw: Any, where: str, converters: dict[str, Any] | None = None) -> Any:
    if not isinstance(raw, dict):
        raise ConfigError(f"[{where}] must be a table")
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown setting(s) in [{where}]: {', '.join(unknown)}")
    values = dict(raw)
    for key, convert in (converters or {}).items():
        if key in values and values[key] is not None:
            values[key] = convert(values[key])
    try:
        return cls(**values)
    except TypeError as exc:
        raise ConfigError(f"invalid [{where}] settings: {exc}") from exc


def _check_type(name: str, value: Any, expected: type | tuple[type, ...]) -> Any:
    if not isinstance(value, expected) or isinstance(value, bool) and expected is int:
        raise ConfigError(f"setting {name!r} has invalid value {value!r}")
    return value


def load_settings(config_path: Path | None = None) -> Settings:
    config_dir, data_dir = default_paths()
    path = Path(config_path).expanduser() if config_path else config_dir / "config.toml"
    raw: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
    elif config_path:
        raise ConfigError(f"config file not found: {path}")

    allowed = {
        "data_dir",
        "rules_dir",
        "limits",
        "clamav",
        "feeds",
        "exclude",
        "workers",
        "follow_symlinks",
        "include_offline",
        "scan_archives",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ConfigError(f"unknown setting(s) in {path}: {', '.join(unknown)}")

    if "data_dir" in raw:
        data_dir = Path(_check_type("data_dir", raw["data_dir"], str)).expanduser()
    rules_dir = config_dir / "rules"
    if "rules_dir" in raw:
        rules_dir = Path(_check_type("rules_dir", raw["rules_dir"], str)).expanduser()

    settings = Settings(config_path=path, data_dir=data_dir, rules_dir=rules_dir)

    if "limits" in raw:
        size_keys = ("max_file_size", "max_member_size", "max_archive_total")
        settings.limits = _build(
            Limits, raw["limits"], "limits", dict.fromkeys(size_keys, parse_size)
        )
    if "clamav" in raw:
        settings.clamav = _build(ClamAVConfig, raw["clamav"], "clamav")
        if settings.clamav.mode not in ("auto", "clamd", "clamscan", "off"):
            raise ConfigError("clamav.mode must be one of: auto, clamd, clamscan, off")
    if "feeds" in raw:
        if not isinstance(raw["feeds"], list):
            raise ConfigError("feeds must be an array of tables ([[feeds]])")
        settings.feeds = [
            _build(FeedConfig, item, "feeds", {"max_size": parse_size}) for item in raw["feeds"]
        ]
    if "exclude" in raw:
        excludes = _check_type("exclude", raw["exclude"], list)
        settings.exclude = [_check_type("exclude", item, str) for item in excludes]
    if "workers" in raw:
        settings.workers = _check_type("workers", raw["workers"], int)
    for key in ("follow_symlinks", "include_offline", "scan_archives"):
        if key in raw:
            setattr(settings, key, _check_type(key, raw[key], bool))

    validate(settings)
    return settings


def validate(settings: Settings) -> None:
    if settings.workers < 1:
        raise ConfigError("workers must be at least 1")
    limits = settings.limits
    for name in (
        "max_archive_depth",
        "max_archive_members",
        "max_compression_ratio",
        "yara_timeout",
    ):
        if getattr(limits, name) < 0:
            raise ConfigError(f"limits.{name} must not be negative")
    seen: set[str] = set()
    for feed in settings.feeds:
        if not FEED_NAME_RE.match(feed.name):
            raise ConfigError(
                f"invalid feed name {feed.name!r}: use lowercase letters, digits, '.', '_' or '-'"
            )
        if feed.name in seen:
            raise ConfigError(f"duplicate feed name: {feed.name!r}")
        seen.add(feed.name)
        if feed.sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", feed.sha256):
            raise ConfigError(f"feed {feed.name!r}: sha256 must be 64 hex characters")


DEFAULT_CONFIG_TEMPLATE = """\
# Venom configuration. Every setting is optional; defaults are shown commented out.

# workers = 4
# follow_symlinks = false
# include_offline = false     # scan cloud-only placeholders (downloads them first)
# scan_archives = true
# exclude = ["*/node_modules", "*.iso"]
# rules_dir = "/path/to/custom/rules"   # *.yar, *.yara and *.hashes files

[limits]
# max_file_size = "256M"      # 0 = unlimited
# max_archive_depth = 3
# max_archive_members = 10000
# max_member_size = "64M"
# max_archive_total = "512M"
# max_compression_ratio = 250
# yara_timeout = 60           # seconds per object

[clamav]
# mode = "auto"               # auto | clamd | clamscan | off
# clamd_socket = "/run/clamav/clamd.ctl"
# clamd_host = "127.0.0.1"
# clamd_port = 3310
# clamscan = "/usr/bin/clamscan"
# freshclam = "/usr/bin/freshclam"

# Rule feeds. Defining any [[feeds]] replaces the defaults.
# [[feeds]]
# name = "yara-forge-core"
# url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
#
# A signed Venom rule bundle (see `venom bundle --help`):
# [[feeds]]
# name = "my-rules"
# url = "https://example.org/venom-rules.zip"
# public_key = "BASE64_ED25519_PUBLIC_KEY"
"""
