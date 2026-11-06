from __future__ import annotations

import os
import socket
import socketserver
import struct
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from venom.config import ClamAVConfig, Limits, Settings
from venom.engines import clamav
from venom.engines.base import EngineError, ScanObject
from venom.engines.clamav import (
    ClamdClient,
    ClamdEngine,
    ClamscanEngine,
    discover,
    find_executable,
    parse_reply,
)
from venom.models import IssueKind, Severity
from venom.runtime import build_runtime
from venom.scanner import Scanner


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ("stream: Win.Test.EICAR_HDB-1 FOUND\0", ("found", "Win.Test.EICAR_HDB-1")),
        ("stream: OK\0", ("ok", None)),
        ("/tmp/a: b.txt: Win.Trojan.X-1 FOUND", ("found", "Win.Trojan.X-1")),
        (r"C:\files\x.exe: OK", ("ok", None)),
        ("INSTREAM size limit exceeded. ERROR", ("error", "INSTREAM size limit exceeded. ERROR")),
        ("", ("error", "")),
    ],
)
def test_parse_reply(reply: str, expected: tuple[str, str | None]) -> None:
    assert parse_reply(reply) == expected


# ------------------------------------------------------------- fake clamd


class FakeClamd(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, signature: bytes) -> None:
        self.signature = signature
        self.received: list[int] = []
        self.reply_override: bytes | None = None
        super().__init__(("127.0.0.1", 0), FakeClamdHandler)

    @property
    def port(self) -> int:
        return self.server_address[1]


class FakeClamdHandler(socketserver.BaseRequestHandler):
    server: FakeClamd

    def _read_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise ConnectionError("client closed early")
            data += chunk
        return data

    def handle(self) -> None:
        command = b""
        while not command.endswith(b"\0"):
            command += self._read_exact(1)
        if command == b"zPING\0":
            self.request.sendall(b"PONG\0")
        elif command == b"zVERSION\0":
            self.request.sendall(b"ClamAV 1.4.1/27500/Fake\0")
        elif command == b"zINSTREAM\0":
            payload = b""
            while length := struct.unpack("!L", self._read_exact(4))[0]:
                payload += self._read_exact(length)
            self.server.received.append(len(payload))
            if self.server.reply_override is not None:
                self.request.sendall(self.server.reply_override)
            elif self.server.signature in payload:
                self.request.sendall(b"stream: Venom.Fake.Marker FOUND\0")
            else:
                self.request.sendall(b"stream: OK\0")


@pytest.fixture
def clamd(marker: bytes) -> Iterator[FakeClamd]:
    server = FakeClamd(marker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_clamd_client(clamd: FakeClamd) -> None:
    client = ClamdClient(port=clamd.port, timeout=5)
    assert client.ping()
    assert client.version().startswith("ClamAV 1.4.1")


def test_clamd_engine_streams_in_chunks(clamd: FakeClamd, marker: bytes, tmp_path: Path) -> None:
    engine = ClamdEngine(ClamdClient(port=clamd.port, timeout=5))
    big = b"\0" * (600 * 1024) + marker
    hit = engine.scan(ScanObject(Path("mem"), "0" * 64, len(big), data=big))
    assert [(d.name, d.severity, d.category) for d in hit] == [
        ("Venom.Fake.Marker", Severity.HIGH, "malware")
    ]
    assert clamd.received == [len(big)]

    on_disk = tmp_path / "clean.bin"
    on_disk.write_bytes(b"clean" * 1000)
    assert engine.scan(ScanObject(on_disk, "0" * 64, 5000, data=None)) == []


def test_clamd_error_reply_raises(clamd: FakeClamd) -> None:
    clamd.reply_override = b"INSTREAM size limit exceeded. ERROR\0"
    engine = ClamdEngine(ClamdClient(port=clamd.port, timeout=5))
    with pytest.raises(EngineError, match="size limit"):
        engine.scan(ScanObject(Path("mem"), "0" * 64, 3, data=b"abc"))


def test_discover_prefers_clamd(clamd: FakeClamd, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clamav, "_SOCKET_CANDIDATES", ())
    engine, info, notices = discover(ClamAVConfig(mode="auto", clamd_port=clamd.port), Limits())
    assert isinstance(engine, ClamdEngine)
    assert info.available and "clamd at 127.0.0.1" in info.detail
    assert notices == []


def test_discover_clamd_mode_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clamav, "_SOCKET_CANDIDATES", ())
    engine, info, notices = discover(ClamAVConfig(mode="clamd", clamd_port=unused_port()), Limits())
    assert engine is None and not info.available
    assert notices and "not reachable" in notices[0]


def test_discover_off() -> None:
    engine, info, notices = discover(ClamAVConfig(mode="off"), Limits())
    assert engine is None and info.detail == "disabled in configuration" and notices == []


def test_scanner_with_clamd_scans_top_level_only(
    clamd: FakeClamd, settings: Settings, samples: Path, marker: bytes
) -> None:
    (samples / "bad.bin").write_bytes(marker)
    (samples / "good.bin").write_bytes(b"fine")
    runtime = build_runtime(settings, use_clamav=False, use_cache=False)
    engine = ClamdEngine(ClamdClient(port=clamd.port, timeout=5))
    report = Scanner(settings, [*runtime.engines, engine]).scan([samples])
    (finding,) = report.findings
    assert {d.engine for d in finding.detections} == {"yara", "clamav"}
    assert sorted(clamd.received) == [4, len(marker)]


# --------------------------------------------------------------- clamscan

FAKE_CLAMSCAN = r"""
import sys
marker = sys.argv[1].encode()
file_list = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--file-list="))
found = False
for path in open(file_list, encoding="utf-8").read().splitlines():
    if "unreported" in path:
        continue
    if "broken" in path:
        print(f"{path}: Can't open file or directory ERROR")
        continue
    data = open(path, "rb").read()
    if marker in data:
        print(f"{path}: Venom.Fake.Clamscan FOUND")
        found = True
    else:
        print(f"{path}: OK")
sys.exit(1 if found else 0)
"""


def fake_clamscan(tmp_path: Path, marker: bytes, exit_code: int | None = None) -> ClamscanEngine:
    script = tmp_path / "fake_clamscan.py"
    body = FAKE_CLAMSCAN if exit_code is None else f"import sys\nsys.exit({exit_code})\n"
    script.write_text(body, encoding="utf-8")
    engine = ClamscanEngine(sys.executable, ClamAVConfig(), Limits(), "fake")
    command = engine._command

    def run(file_list: str) -> list[str]:
        return [sys.executable, str(script), marker.decode(), *command(file_list)[1:]]

    engine._command = run  # type: ignore[method-assign]
    return engine


def test_clamscan_output_parsing(
    settings: Settings, samples: Path, marker: bytes, tmp_path: Path
) -> None:
    for name, data in {
        "bad.bin": marker,
        "good.bin": b"fine",
        "unreported.bin": b"?",
        "broken.bin": b"x",
    }.items():
        (samples / name).write_bytes(data)
    runtime = build_runtime(settings, use_clamav=False, use_cache=False)
    engine = fake_clamscan(tmp_path, marker)
    report = Scanner(settings, [*runtime.engines, engine]).scan([samples])

    (finding,) = report.findings
    assert finding.path == str(samples / "bad.bin")
    assert {d.name for d in finding.detections} == {"Venom_Test_File", "Venom.Fake.Clamscan"}
    issues = {Path(i.path).name: i for i in report.issues}
    assert set(issues) == {"unreported.bin", "broken.bin"}
    assert all(i.kind is IssueKind.ENGINE_ERROR and i.engine == "clamav" for i in issues.values())


def test_clamscan_crash_is_reported(
    settings: Settings, samples: Path, marker: bytes, tmp_path: Path
) -> None:
    (samples / "a.bin").write_bytes(b"x")
    runtime = build_runtime(settings, use_clamav=False, use_cache=False)
    engine = fake_clamscan(tmp_path, marker, exit_code=2)
    report = Scanner(settings, [*runtime.engines, engine]).scan([samples])
    (issue,) = report.issues
    assert issue.kind is IssueKind.ENGINE_ERROR and "clamscan failed" in issue.message


REAL_CLAMSCAN = find_executable("clamscan")


@pytest.mark.skipif(
    REAL_CLAMSCAN is None and not os.environ.get("VENOM_REQUIRE_CLAMAV"),
    reason="ClamAV (clamscan) is not installed",
)
def test_real_clamscan_with_custom_signature(
    settings: Settings, samples: Path, marker: bytes, tmp_path: Path
) -> None:
    database = tmp_path / "venom-test.ndb"
    database.write_text(f"VenomTest.Marker:0:0:{marker.hex()}\n", encoding="ascii")
    settings.clamav = ClamAVConfig(mode="clamscan", database=str(database))
    (samples / "bad.bin").write_bytes(marker)
    (samples / "good.bin").write_bytes(b"fine")

    runtime = build_runtime(settings, use_clamav=True, use_cache=False)
    assert any(isinstance(e, ClamscanEngine) for e in runtime.engines)
    report = Scanner(settings, runtime.engines, runtime.infos).scan([samples])
    (finding,) = report.findings
    names = {d.name for d in finding.detections if d.engine == "clamav"}
    assert names and next(iter(names)).startswith("VenomTest.Marker")
    assert report.complete, report.issues
