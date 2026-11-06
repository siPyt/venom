from __future__ import annotations

from pathlib import Path

import pytest

from helpers import ScanFn
from venom.config import Settings, load_settings
from venom.models import ScanReport
from venom.runtime import build_runtime
from venom.scanner import Scanner
from venom.selftest import make_test_marker


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "venom-home"
    monkeypatch.setenv("VENOM_HOME", str(root))
    monkeypatch.delenv("VENOM_KEY_PASSPHRASE", raising=False)
    return root


@pytest.fixture
def settings(home: Path) -> Settings:
    loaded = load_settings()
    loaded.feeds = []
    loaded.exclude = []
    loaded.workers = 2
    return loaded


@pytest.fixture
def marker() -> bytes:
    return make_test_marker()


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    directory = tmp_path / "samples"
    directory.mkdir()
    return directory


@pytest.fixture
def scan(settings: Settings) -> ScanFn:
    def run(*targets: Path | str, **kwargs: object) -> ScanReport:
        runtime = build_runtime(settings, use_clamav=False, use_cache=False)
        try:
            scanner = Scanner(settings, runtime.engines, runtime.infos, runtime.notices)
            return scanner.scan(targets, **kwargs)
        finally:
            runtime.close()

    return run
