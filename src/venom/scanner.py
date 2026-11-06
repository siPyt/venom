"""Scan orchestration: enumerate files, run engines, inspect archives, and collect results."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from venom import archives
from venom.config import MiB, Settings, format_size
from venom.engines.base import Engine, EngineError, EngineTimeout, ScanObject
from venom.fsutil import (
    NotRegularFile,
    PathFilter,
    is_link_entry,
    is_offline_placeholder,
    open_regular,
)
from venom.models import Detection, EngineInfo, Finding, Issue, IssueKind, ScanReport

IN_MEMORY_LIMIT = 32 * MiB
_HASH_CHUNK = MiB
_NEEDS_ENTRY_STAT = os.name == "nt" or sys.platform == "darwin"

Progress = Callable[[str], None]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _os_message(exc: OSError) -> str:
    return exc.strerror or str(exc)


@dataclass
class _Outcome:
    path: str
    sha256: str | None = None
    findings: list[Finding] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    bytes_scanned: int = 0
    members: int = 0
    scanned: bool = False
    special: bool = False
    vanished: bool = False
    batch: bool = False


@dataclass(frozen=True)
class _WalkItem:
    path: Path
    explicit: bool


def _dedupe(detections: Iterable[Detection]) -> list[Detection]:
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for detection in detections:
        key = (detection.engine, detection.name, detection.source)
        if key not in seen:
            seen.add(key)
            unique.append(detection)
    return unique


class Scanner:
    def __init__(
        self,
        settings: Settings,
        engines: list[Engine],
        engine_infos: list[EngineInfo] | None = None,
        notices: list[str] | None = None,
    ) -> None:
        self.settings = settings
        self.limits = settings.limits
        self.engines = [e for e in engines if not e.batch]
        self.batch_engines = [e for e in engines if e.batch]
        self.engine_infos = (
            engine_infos if engine_infos is not None else [e.info() for e in engines]
        )
        self.notices = list(notices or [])
        # Venom's own rule files would match themselves, so they are never scanned.
        self.filter = PathFilter(
            settings.exclude, internal_dirs=[settings.data_dir, settings.rules_dir]
        )

    # ----------------------------------------------------------------- public

    def scan(
        self,
        targets: Iterable[str | os.PathLike[str]],
        *,
        cancel: threading.Event | None = None,
        progress: Progress | None = None,
    ) -> ScanReport:
        cancel = cancel or threading.Event()
        targets = [Path(t) for t in targets]
        started = time.monotonic()
        report = ScanReport(
            targets=[str(t) for t in targets],
            started_at=_now(),
            engines=list(self.engine_infos),
            notices=list(self.notices),
        )
        state = _State(report)
        try:
            self._run_pool(targets, cancel, state, progress)
            if self.batch_engines and state.batch_paths and not cancel.is_set():
                self._run_batch(cancel, state, progress)
        except KeyboardInterrupt:
            cancel.set()

        stats = report.stats
        if stats.offline_skipped:
            report.notices.append(
                f"{stats.offline_skipped} cloud-only file(s) were not scanned because reading them "
                "would download them. Use --include-offline to scan them."
            )
        report.cancelled = cancel.is_set()
        report.findings.sort(key=lambda f: (-f.severity, f.location))
        report.finished_at = _now()
        report.duration_seconds = time.monotonic() - started
        return report

    # ------------------------------------------------------------- execution

    def _run_pool(
        self, targets: list[Path], cancel: threading.Event, state: _State, progress: Progress | None
    ) -> None:
        workers = self.settings.workers
        pending: set[Future[_Outcome]] = set()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="venom-scan") as pool:
            try:
                for item in self._walk(targets, state.report):
                    if cancel.is_set():
                        break
                    pending.add(pool.submit(self._scan_file, item, cancel))
                    while len(pending) >= workers * 4:
                        pending = self._drain(pending, state, progress)
                while pending:
                    pending = self._drain(pending, state, progress)
            except KeyboardInterrupt:
                cancel.set()
                for future in pending:
                    future.cancel()
        for future in pending:
            if future.done() and not future.cancelled():
                state.merge(future.result())

    def _drain(
        self, pending: set[Future[_Outcome]], state: _State, progress: Progress | None
    ) -> set[Future[_Outcome]]:
        # A short timeout keeps Ctrl+C responsive on every platform.
        done, remaining = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
        for future in done:
            outcome = future.result()
            state.merge(outcome)
            if progress and outcome.scanned:
                progress(f"{state.report.stats.files_scanned} files scanned: {outcome.path}")
        return remaining

    def _run_batch(self, cancel: threading.Event, state: _State, progress: Progress | None) -> None:
        for engine in self.batch_engines:
            if cancel.is_set():
                return
            if progress:
                progress(f"{engine.name}: scanning {len(state.batch_paths)} files...")
            try:
                result = engine.scan_batch(state.batch_paths, cancel)
            except EngineError as exc:
                state.report.issues.append(
                    Issue("(all files)", IssueKind.ENGINE_ERROR, str(exc), engine=engine.name)
                )
                continue
            for path, detections in result.detections.items():
                state.add_top_level(path, detections)
            state.report.issues.extend(result.issues)

    # -------------------------------------------------------------- walking

    def _walk(self, targets: list[Path], report: ScanReport) -> Iterator[_WalkItem]:
        for target in targets:
            try:
                st = os.stat(target)
            except FileNotFoundError:
                report.issues.append(Issue(str(target), IssueKind.NOT_FOUND, "path does not exist"))
                continue
            except OSError as exc:
                report.issues.append(Issue(str(target), IssueKind.UNREADABLE, _os_message(exc)))
                continue
            if stat.S_ISDIR(st.st_mode):
                self.filter.add_root(target)
                yield from self._walk_dir(target, report)
            elif stat.S_ISREG(st.st_mode):
                yield _WalkItem(target, explicit=True)
            else:
                report.stats.special_skipped += 1

    def _walk_dir(self, root: Path, report: ScanReport) -> Iterator[_WalkItem]:
        follow = self.settings.follow_symlinks
        stats = report.stats
        visited: set[tuple[int, int]] = set()
        if follow:
            root_stat = os.stat(root)
            visited.add((root_stat.st_dev, root_stat.st_ino))
        stack = [str(root)]
        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda e: e.name)
            except FileNotFoundError:
                stats.vanished += 1
                continue
            except OSError as exc:
                report.issues.append(
                    Issue(
                        directory,
                        IssueKind.UNREADABLE,
                        f"cannot list directory: {_os_message(exc)}",
                    )
                )
                continue
            subdirs: list[str] = []
            for entry in entries:
                if self.filter.excluded(entry.path):
                    stats.excluded += 1
                    continue
                try:
                    if not follow and is_link_entry(entry):
                        stats.links_skipped += 1
                    elif entry.is_dir(follow_symlinks=follow):
                        if follow:
                            st = os.stat(entry.path)
                            key = (st.st_dev, st.st_ino)
                            if key in visited:
                                stats.links_skipped += 1
                                continue
                            visited.add(key)
                        subdirs.append(entry.path)
                    elif entry.is_file(follow_symlinks=follow):
                        if (
                            _NEEDS_ENTRY_STAT
                            and not self.settings.include_offline
                            and is_offline_placeholder(entry.stat(follow_symlinks=follow))
                        ):
                            stats.offline_skipped += 1
                            continue
                        yield _WalkItem(Path(entry.path), explicit=False)
                    else:
                        stats.special_skipped += 1
                except FileNotFoundError:
                    stats.vanished += 1
                except OSError as exc:
                    report.issues.append(Issue(entry.path, IssueKind.UNREADABLE, _os_message(exc)))
            stack.extend(reversed(subdirs))

    # ------------------------------------------------------------- scanning

    def _scan_file(self, item: _WalkItem, cancel: threading.Event) -> _Outcome:
        outcome = _Outcome(str(item.path))
        if cancel.is_set():
            return outcome
        try:
            self._scan_file_inner(item, cancel, outcome)
        except Exception as exc:  # noqa: BLE001 - one bad file must never abort the whole scan
            outcome.issues.append(
                Issue(outcome.path, IssueKind.ENGINE_ERROR, f"internal error: {exc!r}")
            )
        return outcome

    def _scan_file_inner(self, item: _WalkItem, cancel: threading.Event, outcome: _Outcome) -> None:
        path = item.path
        try:
            fh, st = open_regular(
                path, follow_symlinks=item.explicit or self.settings.follow_symlinks
            )
        except NotRegularFile:
            outcome.special = True
            return
        except FileNotFoundError:
            outcome.vanished = True
            return
        except OSError as exc:
            outcome.issues.append(Issue(outcome.path, IssueKind.UNREADABLE, _os_message(exc)))
            return

        with fh:
            max_size = self.limits.max_file_size
            if max_size and st.st_size > max_size:
                message = (
                    f"{format_size(st.st_size)} exceeds the {format_size(max_size)} file size limit"
                )
                outcome.issues.append(Issue(outcome.path, IssueKind.TOO_LARGE, message))
                return
            try:
                data = (
                    archives.read_bounded(fh, IN_MEMORY_LIMIT)
                    if st.st_size <= IN_MEMORY_LIMIT
                    else None
                )
                if data is not None:
                    sha256, size = hashlib.sha256(data).hexdigest(), len(data)
                else:
                    sha256, size = self._hash_stream(fh, cancel)
            except OSError as exc:
                outcome.issues.append(Issue(outcome.path, IssueKind.UNREADABLE, _os_message(exc)))
                return
            if cancel.is_set():
                return

            outcome.sha256 = sha256
            outcome.scanned = True
            outcome.bytes_scanned += size
            outcome.batch = bool(self.batch_engines)
            obj = ScanObject(path=path, sha256=sha256, size=size, data=data)
            self._scan_object(obj, outcome, archives.Budget.from_limits(self.limits), cancel, fh)

    @staticmethod
    def _hash_stream(fh: BinaryIO, cancel: threading.Event) -> tuple[str, int]:
        fh.seek(0)
        digest = hashlib.sha256()
        size = 0
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
            if cancel.is_set():
                break
        return digest.hexdigest(), size

    def _scan_object(
        self,
        obj: ScanObject,
        outcome: _Outcome,
        budget: archives.Budget,
        cancel: threading.Event,
        stream: BinaryIO | None = None,
    ) -> None:
        detections: list[Detection] = []
        for engine in self.engines:
            if obj.depth and not engine.scans_members:
                continue
            try:
                detections.extend(engine.scan(obj))
            except EngineTimeout as exc:
                outcome.issues.append(
                    Issue(outcome.path, IssueKind.TIMEOUT, str(exc), obj.member, engine.name)
                )
            except EngineError as exc:
                outcome.issues.append(
                    Issue(outcome.path, IssueKind.ENGINE_ERROR, str(exc), obj.member, engine.name)
                )
            except Exception as exc:  # noqa: BLE001 - isolate engine bugs to one object
                outcome.issues.append(
                    Issue(
                        outcome.path,
                        IssueKind.ENGINE_ERROR,
                        f"unexpected failure: {exc!r}",
                        obj.member,
                        engine.name,
                    )
                )
        if detections:
            outcome.findings.append(
                Finding(
                    path=outcome.path,
                    sha256=outcome.sha256,
                    detections=_dedupe(detections),
                    member=obj.member,
                    member_sha256=obj.sha256 if obj.depth else None,
                )
            )

        if not self.settings.scan_archives or not self.limits.max_archive_depth or cancel.is_set():
            return
        if obj.data is not None:
            source: BinaryIO = io.BytesIO(obj.data)
        elif stream is not None:
            source = stream
            source.seek(0)
        else:
            return
        kind = archives.sniff(source.read(512))
        source.seek(0)
        if kind is None:
            return
        if obj.depth >= self.limits.max_archive_depth:
            outcome.issues.append(
                Issue(
                    outcome.path,
                    IssueKind.ARCHIVE_LIMIT,
                    f"nested archive depth limit ({self.limits.max_archive_depth}) reached; "
                    "contents not scanned",
                    obj.member,
                )
            )
            return

        container = obj.member[-1] if obj.member else obj.path.name
        for item in archives.iter_archive(kind, source, container, self.limits, budget):
            if cancel.is_set():
                return
            if isinstance(item, archives.Problem):
                member = obj.member + ((item.name,) if item.name else ())
                outcome.issues.append(Issue(outcome.path, item.kind, item.message, member))
                continue
            child = ScanObject(
                path=obj.path,
                sha256=hashlib.sha256(item.data).hexdigest(),
                size=len(item.data),
                data=item.data,
                member=obj.member + (item.name,),
            )
            outcome.members += 1
            outcome.bytes_scanned += child.size
            self._scan_object(child, outcome, budget, cancel)


class _State:
    """Result accumulation; only touched from the coordinating thread."""

    def __init__(self, report: ScanReport) -> None:
        self.report = report
        self.batch_paths: list[Path] = []
        self.sha_by_path: dict[str, str] = {}
        self.top_level: dict[str, Finding] = {}

    def merge(self, outcome: _Outcome) -> None:
        stats = self.report.stats
        if outcome.scanned:
            stats.files_scanned += 1
        stats.bytes_scanned += outcome.bytes_scanned
        stats.members_scanned += outcome.members
        stats.special_skipped += outcome.special
        stats.vanished += outcome.vanished
        for finding in outcome.findings:
            self.report.findings.append(finding)
            if not finding.member:
                self.top_level[finding.path] = finding
        self.report.issues.extend(outcome.issues)
        if outcome.batch and outcome.sha256:
            self.batch_paths.append(Path(outcome.path))
            self.sha_by_path[outcome.path] = outcome.sha256

    def add_top_level(self, path: str, detections: list[Detection]) -> None:
        finding = self.top_level.get(path)
        if finding is None:
            finding = Finding(path=path, sha256=self.sha_by_path.get(path), detections=[])
            self.top_level[path] = finding
            self.report.findings.append(finding)
        finding.detections[:] = _dedupe([*finding.detections, *detections])
