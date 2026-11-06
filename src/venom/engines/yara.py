"""YARA-X rule engine with a compiled-rules cache."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import threading
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

import yara_x

from venom.engines.base import Engine, EngineError, EngineTimeout, ScanObject
from venom.models import Detection, EngineInfo, Severity

_RULE_RE = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]\w*", re.MULTILINE)


def yara_x_version() -> str:
    try:
        return metadata.version("yara-x")
    except metadata.PackageNotFoundError:
        return "unknown"


@dataclass(frozen=True)
class RuleSource:
    namespace: str
    origin: str
    text: str


@dataclass
class CompiledRules:
    rules: yara_x.Rules | None
    rule_count: int = 0
    origins: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def count_rules(text: str) -> int:
    return len(_RULE_RE.findall(text))


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__


def compile_sources(sources: list[RuleSource], *, strict: bool = False) -> CompiledRules:
    """Compile sources, skipping (or, if ``strict``, raising on) any that fail."""
    compiler = yara_x.Compiler()
    result = CompiledRules(rules=None)
    for source in sources:
        compiler.new_namespace(source.namespace)
        try:
            compiler.add_source(source.text, origin=source.origin)
        except yara_x.CompileError as exc:
            if strict:
                raise
            result.errors.append(f"{source.origin}: {_first_line(exc)}")
            continue
        result.origins.append(source.origin)
        result.rule_count += count_rules(source.text)
    if result.origins:
        result.rules = compiler.build()
    return result


def _cache_key(sources: list[RuleSource]) -> str:
    digest = hashlib.sha256(f"venom-yara-cache-v1\0{yara_x_version()}\0".encode())
    for source in sources:
        for part in (source.namespace, source.origin, source.text):
            encoded = part.encode("utf-8", "replace")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()[:32]


def load_rules(sources: list[RuleSource], cache_dir: Path | None) -> CompiledRules:
    """Compile rules, reusing a serialized copy when the exact same sources were seen before."""
    if not sources:
        return CompiledRules(rules=None)
    if cache_dir is None:
        return compile_sources(sources)

    key = _cache_key(sources)
    blob_path = cache_dir / f"yara-{key}.bin"
    meta_path = cache_dir / f"yara-{key}.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        with open(blob_path, "rb") as fh:
            rules = yara_x.Rules.deserialize_from(fh) if meta.get("compiled") else None
        return CompiledRules(rules, meta["rule_count"], meta["origins"], meta["errors"])
    except Exception:  # noqa: BLE001 - a missing or corrupt cache just means recompiling
        pass

    compiled = compile_sources(sources)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        buffer = io.BytesIO()
        if compiled.rules is not None:
            compiled.rules.serialize_into(buffer)
        meta = {
            "compiled": compiled.rules is not None,
            "rule_count": compiled.rule_count,
            "origins": compiled.origins,
            "errors": compiled.errors,
        }
        for path, payload in (
            (blob_path, buffer.getvalue()),
            (meta_path, json.dumps(meta).encode()),
        ):
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(payload)
            os.replace(tmp, path)
        for stale in cache_dir.glob("yara-*"):
            if stale.name not in (blob_path.name, meta_path.name):
                stale.unlink(missing_ok=True)
    except OSError:
        pass
    return compiled


def _severity_from_meta(meta: dict[str, object]) -> Severity:
    explicit = Severity.parse(meta.get("severity"))
    if explicit is not None:
        return explicit
    score = meta.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        if score >= 80:
            return Severity.HIGH
        if score >= 60:
            return Severity.MEDIUM
        return Severity.LOW
    return Severity.MEDIUM


class YaraEngine(Engine):
    name = "yara"

    def __init__(self, compiled: CompiledRules, timeout: int = 60) -> None:
        self._compiled = compiled
        self._timeout = timeout
        self._local = threading.local()

    @property
    def rule_count(self) -> int:
        return self._compiled.rule_count

    def info(self) -> EngineInfo:
        compiled = self._compiled
        if compiled.rules is None:
            return EngineInfo(self.name, False, yara_x_version(), "no rules loaded")
        return EngineInfo(
            self.name,
            True,
            yara_x_version(),
            f"{compiled.rule_count} rules from {len(compiled.origins)} source(s)",
        )

    def _scanner(self) -> yara_x.Scanner:
        # yara-x scanners are not thread-safe; each worker thread gets its own.
        scanner = getattr(self._local, "scanner", None)
        if scanner is None:
            scanner = yara_x.Scanner(self._compiled.rules)
            if self._timeout:
                scanner.set_timeout(self._timeout)
            scanner.max_matches_per_pattern(1000)
            self._local.scanner = scanner
        return scanner

    def scan(self, obj: ScanObject) -> list[Detection]:
        if self._compiled.rules is None:
            return []
        scanner = self._scanner()
        try:
            if obj.data is not None:
                results = scanner.scan(obj.data)
            else:
                results = scanner.scan_file(str(obj.path))
        except yara_x.TimeoutError as exc:
            raise EngineTimeout(f"YARA scan timed out after {self._timeout}s") from exc
        except yara_x.ScanError as exc:
            raise EngineError(f"YARA scan failed: {_first_line(exc)}") from exc
        return [self._detection(rule) for rule in results.matching_rules]

    def _detection(self, rule: yara_x.Rule) -> Detection:
        meta: dict[str, object] = {}
        for key, value in rule.metadata:
            meta.setdefault(key, value)
        severity = _severity_from_meta(meta)
        category = meta.get("category")
        if not isinstance(category, str) or not category:
            category = "malware" if severity >= Severity.HIGH else "suspicious"
        description = meta.get("description")
        return Detection(
            engine=self.name,
            name=rule.identifier,
            severity=severity,
            category=category,
            description=description if isinstance(description, str) else "",
            source=rule.namespace,
        )
