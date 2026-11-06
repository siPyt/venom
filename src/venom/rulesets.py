"""Where rules come from: built-in data, installed feeds, and the user's rules directory."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from venom.config import Settings
from venom.engines.yara import RuleSource

YARA_SUFFIXES = (".yar", ".yara")
HASH_SUFFIX = ".hashes"
FEED_STATE_FILE = ".venom-feed.json"
STALE_AFTER_DAYS = 7


@dataclass
class RuleSet:
    yara: list[RuleSource] = field(default_factory=list)
    hashes: list[tuple[str, str]] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        p
        for p in directory.rglob("*")
        if p.is_file() and p.suffix.lower() in (*YARA_SUFFIXES, HASH_SUFFIX)
    )


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _add_directory(
    ruleset: RuleSet, directory: Path, label: str, *, per_file_namespace: bool
) -> None:
    for path in rule_files(directory):
        relative = path.relative_to(directory).as_posix()
        origin = f"{label}/{relative}"
        try:
            text = _read(path)
        except OSError as exc:
            ruleset.notices.append(f"Could not read rule file {path}: {exc.strerror or exc}")
            continue
        if path.suffix.lower() == HASH_SUFFIX:
            ruleset.hashes.append((origin, text))
        else:
            namespace = f"{label}:{relative}" if per_file_namespace else label
            ruleset.yara.append(RuleSource(namespace, origin, text))


def feed_current_dir(settings: Settings, name: str) -> Path:
    return settings.feeds_dir / name / "current"


def read_feed_state(directory: Path) -> dict[str, Any] | None:
    try:
        state = json.loads((directory / FEED_STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def feed_age_days(state: dict[str, Any]) -> float | None:
    try:
        fetched = datetime.fromisoformat(state["fetched_at"])
    except (KeyError, TypeError, ValueError):
        return None
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=UTC)
    return (datetime.now(UTC) - fetched).total_seconds() / 86400


def collect(settings: Settings) -> RuleSet:
    ruleset = RuleSet()
    data = resources.files("venom") / "data"
    ruleset.yara.append(
        RuleSource("builtin", "builtin/builtin.yar", (data / "builtin.yar").read_text("utf-8"))
    )
    ruleset.hashes.append(("builtin/builtin.hashes", (data / "builtin.hashes").read_text("utf-8")))

    for feed in settings.feeds:
        if feed.enabled:
            _add_directory(
                ruleset,
                feed_current_dir(settings, feed.name),
                f"feed:{feed.name}",
                per_file_namespace=False,
            )
    _add_directory(ruleset, settings.rules_dir, "user", per_file_namespace=True)
    return ruleset


def freshness_notices(settings: Settings) -> list[str]:
    notices: list[str] = []
    enabled = [feed for feed in settings.feeds if feed.enabled]
    installed = 0
    for feed in enabled:
        state = read_feed_state(feed_current_dir(settings, feed.name))
        if state is None:
            continue
        installed += 1
        age = feed_age_days(state)
        if age is not None and age > STALE_AFTER_DAYS:
            notices.append(
                f"Rule feed '{feed.name}' was last updated {age:.0f} days ago. Run `venom update`."
            )
    if enabled and installed == 0:
        notices.append(
            "No rule feeds are installed, so only built-in test signatures and your own rules "
            "are active. Run `venom update` to download community YARA rules."
        )
    return notices
