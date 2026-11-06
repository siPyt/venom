"""Assemble the configured detection engines."""

from __future__ import annotations

from dataclasses import dataclass, field

from venom.config import Settings
from venom.engines.base import Engine
from venom.engines.clamav import discover
from venom.engines.hashes import HashEngine, HashListError
from venom.engines.yara import YaraEngine, load_rules
from venom.models import EngineInfo
from venom.rulesets import collect, freshness_notices


@dataclass
class Runtime:
    engines: list[Engine]
    infos: list[EngineInfo]
    notices: list[str] = field(default_factory=list)

    def close(self) -> None:
        for engine in self.engines:
            engine.close()


def build_runtime(
    settings: Settings, *, use_clamav: bool = True, use_cache: bool = True
) -> Runtime:
    ruleset = collect(settings)
    notices = list(ruleset.notices)

    hash_engine = HashEngine()
    for origin, text in ruleset.hashes:
        try:
            hash_engine.add(origin, text)
        except HashListError as exc:
            notices.append(f"Skipped invalid hash list: {exc}")

    compiled = load_rules(ruleset.yara, settings.cache_dir if use_cache else None)
    notices.extend(f"Skipped YARA rules that failed to compile: {err}" for err in compiled.errors)
    yara_engine = YaraEngine(compiled, settings.limits.yara_timeout)

    engines: list[Engine] = [hash_engine, yara_engine]
    infos = [hash_engine.info(), yara_engine.info()]
    if use_clamav:
        clamav, info, clamav_notices = discover(settings.clamav, settings.limits)
        if clamav is not None:
            engines.append(clamav)
        infos.append(info)
        notices.extend(clamav_notices)
    else:
        infos.append(EngineInfo("clamav", False, detail="disabled for this run"))
    notices.extend(freshness_notices(settings))
    return Runtime(engines, infos, notices)
