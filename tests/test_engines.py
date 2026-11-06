from __future__ import annotations

from pathlib import Path

import pytest
import yara_x

from venom.engines import yara as yara_mod
from venom.engines.base import ScanObject, classify_signature
from venom.engines.hashes import HashEngine, HashListError, parse_hash_list
from venom.engines.yara import (
    RuleSource,
    YaraEngine,
    compile_sources,
    count_rules,
    load_rules,
)
from venom.models import Severity

SHA_A = "a" * 64
SHA_B = "B" * 64


def obj(data: bytes, sha: str = "0" * 64) -> ScanObject:
    return ScanObject(path=Path("sample.bin"), sha256=sha, size=len(data), data=data)


# ------------------------------------------------------------------ hashes


def test_parse_hash_list() -> None:
    text = f"# comment\n\n{SHA_A} Win.Trojan.Example\n{SHA_B}\n  {SHA_A[:-1]}c\tPUA.Tool  \n"
    entries = parse_hash_list(text, "list.hashes")
    assert entries[SHA_A] == "Win.Trojan.Example"
    assert entries[SHA_B.lower()] == f"Hash.Blocklisted.{'b' * 12}"
    assert entries[SHA_A[:-1] + "c"] == "PUA.Tool"


def test_parse_hash_list_reports_line_numbers() -> None:
    with pytest.raises(HashListError, match=r"bad\.hashes:2"):
        parse_hash_list(f"{SHA_A}\nnot-a-hash Name\n", "bad.hashes")


def test_hash_engine_matches() -> None:
    engine = HashEngine([("mine.hashes", f"{SHA_A} PUA.Win.Miner\n")])
    assert engine.scan(obj(b"", sha="f" * 64)) == []
    (detection,) = engine.scan(obj(b"", sha=SHA_A))
    assert detection.name == "PUA.Win.Miner"
    assert detection.severity is Severity.LOW
    assert detection.category == "pua"
    assert detection.source == "mine.hashes"


@pytest.mark.parametrize(
    ("name", "severity", "category"),
    [
        ("Win.Trojan.Agent-1", Severity.HIGH, "malware"),
        ("PUA.Win.Adware", Severity.LOW, "pua"),
        ("Heuristics.Phishing.Email", Severity.MEDIUM, "heuristic"),
        ("Eicar-Signature", Severity.LOW, "test"),
        ("Test.Something", Severity.LOW, "test"),
    ],
)
def test_classify_signature(name: str, severity: Severity, category: str) -> None:
    assert classify_signature(name) == (severity, category)


# -------------------------------------------------------------------- yara

RULES = """
rule Critical_Rule {
    meta: severity = "critical" category = "ransomware" description = "crit"
    strings: $a = "crit-token"
    condition: $a
}
rule Scored_High { meta: score = 85 strings: $a = "high-token" condition: $a }
rule Scored_Medium { meta: score = 65 strings: $a = "medium-token" condition: $a }
rule Scored_Low { meta: score = 10 strings: $a = "low-token" condition: $a }
private rule Helper { strings: $a = "plain-token" condition: $a }
rule Plain { condition: Helper }
"""


def engine_for(text: str) -> YaraEngine:
    return YaraEngine(compile_sources([RuleSource("test", "test.yar", text)]))


def test_count_rules() -> None:
    assert count_rules(RULES) == 6
    assert count_rules("global private rule G { condition: true }") == 1


@pytest.mark.parametrize(
    ("data", "name", "severity", "category"),
    [
        (b"xx crit-token xx", "Critical_Rule", Severity.CRITICAL, "ransomware"),
        (b"high-token", "Scored_High", Severity.HIGH, "malware"),
        (b"medium-token", "Scored_Medium", Severity.MEDIUM, "suspicious"),
        (b"low-token", "Scored_Low", Severity.LOW, "suspicious"),
        (b"plain-token", "Plain", Severity.MEDIUM, "suspicious"),
    ],
)
def test_yara_severity_mapping(data: bytes, name: str, severity: Severity, category: str) -> None:
    (detection,) = engine_for(RULES).scan(obj(data))
    assert (detection.name, detection.severity, detection.category) == (name, severity, category)
    assert detection.source == "test"


def test_yara_scans_files_on_disk(tmp_path: Path) -> None:
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"\0" * 1000 + b"high-token")
    target = ScanObject(path=sample, sha256="0" * 64, size=1010, data=None)
    assert [d.name for d in engine_for(RULES).scan(target)] == ["Scored_High"]


def test_no_rules_means_unavailable_engine() -> None:
    engine = YaraEngine(compile_sources([]))
    assert engine.scan(obj(b"anything")) == []
    assert engine.info().available is False


def test_bad_source_is_skipped_unless_strict() -> None:
    sources = [
        RuleSource("a", "bad.yar", "rule Bad { condition: nope }"),
        RuleSource("b", "good.yar", 'rule Good { strings: $a = "ok" condition: $a }'),
    ]
    compiled = compile_sources(sources)
    assert compiled.origins == ["good.yar"]
    assert compiled.rule_count == 1
    assert compiled.errors and compiled.errors[0].startswith("bad.yar:")
    assert [d.name for d in YaraEngine(compiled).scan(obj(b"ok"))] == ["Good"]
    with pytest.raises(yara_x.CompileError):
        compile_sources(sources, strict=True)


def test_namespaces_isolate_duplicate_rule_names() -> None:
    sources = [
        RuleSource("user:a.yar", "a.yar", 'rule Same { strings: $a = "one" condition: $a }'),
        RuleSource("user:b.yar", "b.yar", 'rule Same { strings: $a = "two" condition: $a }'),
    ]
    compiled = compile_sources(sources)
    assert not compiled.errors
    hits = YaraEngine(compiled).scan(obj(b"one two"))
    assert sorted(d.source for d in hits) == ["user:a.yar", "user:b.yar"]


def test_rule_cache_is_reused_and_invalidated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    first = [RuleSource("t", "t.yar", 'rule One { strings: $a = "one" condition: $a }')]
    compiled = load_rules(first, cache)
    assert compiled.rule_count == 1
    assert len(list(cache.glob("yara-*.bin"))) == 1

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("cache should have been used")

    with monkeypatch.context() as m:
        m.setattr(yara_mod, "compile_sources", fail)
        cached = load_rules(first, cache)
    assert cached.rule_count == 1
    assert [d.name for d in YaraEngine(cached).scan(obj(b"one"))] == ["One"]

    second = [RuleSource("t", "t.yar", 'rule Two { strings: $a = "two" condition: $a }')]
    assert load_rules(second, cache).rule_count == 1
    assert len(list(cache.glob("yara-*.bin"))) == 1, "stale cache entries are removed"


def test_corrupt_cache_falls_back_to_compiling(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    sources = [RuleSource("t", "t.yar", 'rule One { strings: $a = "one" condition: $a }')]
    load_rules(sources, cache)
    for blob in cache.glob("yara-*.bin"):
        blob.write_bytes(b"garbage")
    compiled = load_rules(sources, cache)
    assert [d.name for d in YaraEngine(compiled).scan(obj(b"one"))] == ["One"]
