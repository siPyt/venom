from __future__ import annotations

from pathlib import Path

import pytest

from venom.config import (
    DEFAULT_CONFIG_TEMPLATE,
    DEFAULT_FEEDS,
    ConfigError,
    Limits,
    MiB,
    format_size,
    load_settings,
    parse_size,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0),
        (1048576, MiB),
        ("512", 512),
        ("512K", 512 * 1024),
        ("256M", 256 * MiB),
        ("256mb", 256 * MiB),
        ("2GiB", 2 * 1024 * MiB),
        ("1.5M", int(1.5 * MiB)),
    ],
)
def test_parse_size(value: int | str, expected: int) -> None:
    assert parse_size(value) == expected


@pytest.mark.parametrize("value", ["", "abc", "12Q", "-5M", -1, True])
def test_parse_size_rejects_invalid(value: object) -> None:
    with pytest.raises(ConfigError):
        parse_size(value)  # type: ignore[arg-type]


def test_format_size() -> None:
    assert format_size(512) == "512 B"
    assert format_size(1536) == "1.5 KiB"
    assert format_size(3 * MiB) == "3.0 MiB"


def write_config(home: Path, text: str) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_use_venom_home(home: Path) -> None:
    settings = load_settings()
    assert settings.data_dir == home.resolve()
    assert settings.config_path == home.resolve() / "config.toml"
    assert settings.rules_dir == home.resolve() / "rules"
    assert settings.quarantine_dir == settings.data_dir / "quarantine"
    assert [f.name for f in settings.feeds] == [f.name for f in DEFAULT_FEEDS]
    assert settings.limits == Limits()


def test_default_template_loads_as_defaults(home: Path) -> None:
    write_config(home, DEFAULT_CONFIG_TEMPLATE)
    settings = load_settings()
    assert settings.limits == Limits()
    assert settings.clamav.mode == "auto"


def test_full_config(home: Path) -> None:
    write_config(
        home,
        """
workers = 3
follow_symlinks = true
scan_archives = false
exclude = ["*.iso", "*/node_modules"]

[limits]
max_file_size = "1G"
max_member_size = 1024
max_archive_depth = 5

[clamav]
mode = "clamscan"
database = "/tmp/db"

[[feeds]]
name = "mine"
url = "https://example.org/rules.zip"
max_size = "10M"
""",
    )
    settings = load_settings()
    assert settings.workers == 3
    assert settings.follow_symlinks is True
    assert settings.scan_archives is False
    assert settings.exclude == ["*.iso", "*/node_modules"]
    assert settings.limits.max_file_size == 1024 * MiB
    assert settings.limits.max_member_size == 1024
    assert settings.limits.max_archive_depth == 5
    assert settings.clamav.mode == "clamscan"
    assert settings.clamav.database == "/tmp/db"
    assert len(settings.feeds) == 1
    assert settings.feeds[0].max_size == 10 * MiB


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("colour = 'red'", "unknown setting"),
        ("[limits]\nmax_size = 1", "unknown setting"),
        ("workers = true", "invalid value"),
        ("workers = 0", "at least 1"),
        ("exclude = 'x'", "invalid value"),
        ("follow_symlinks = 'yes'", "invalid value"),
        ("[clamav]\nmode = 'sometimes'", "clamav.mode"),
        ("[limits]\nmax_archive_depth = -1", "must not be negative"),
        ("[limits]\nmax_file_size = 'huge'", "invalid size"),
        ("[[feeds]]\nname = 'Bad Name'\nurl = 'https://x'", "invalid feed name"),
        (
            "[[feeds]]\nname = 'a'\nurl = 'https://x'\n[[feeds]]\nname = 'a'\nurl = 'https://y'",
            "duplicate feed",
        ),
        ("[[feeds]]\nname = 'a'\nurl = 'https://x'\nsha256 = 'abc'", "64 hex"),
        ("[[feeds]]\nname = 'a'", "invalid [feeds]"),
        ("this is not toml", "cannot read config"),
    ],
)
def test_invalid_config(home: Path, text: str, message: str) -> None:
    write_config(home, text)
    with pytest.raises(ConfigError, match=message.replace("[", r"\[")):
        load_settings()


def test_explicit_missing_config_is_an_error(tmp_path: Path, home: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "nope.toml")
