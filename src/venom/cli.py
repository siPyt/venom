"""Command-line interface for Venom."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from venom import __version__
from venom.bundles import BundleError, create_bundle, generate_keypair
from venom.config import (
    DEFAULT_CONFIG_TEMPLATE,
    ConfigError,
    Settings,
    format_size,
    load_settings,
    parse_size,
    validate,
)
from venom.engines.yara import RuleSource, compile_sources, load_rules
from venom.models import Detection, ScanReport
from venom.quarantine import QuarantineError, QuarantineStore
from venom.rulesets import (
    HASH_SUFFIX,
    collect,
    feed_age_days,
    feed_current_dir,
    read_feed_state,
    rule_files,
)
from venom.runtime import build_runtime
from venom.scanner import Scanner
from venom.selftest import run_selftest
from venom.updates import rollback_feed, run_freshclam, update_feed

EXIT_CLEAN = 0
EXIT_THREATS = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_ERROR = 4
EXIT_CANCELLED = 130

MAX_ISSUES_SHOWN = 20


def _err(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class _ProgressLine:
    """Single-line, throttled progress display on an interactive stderr."""

    def __init__(self) -> None:
        self._last = 0.0
        self._shown = False

    def __call__(self, message: str) -> None:
        now = time.monotonic()
        if now - self._last < 0.1:
            return
        self._last = now
        width = max(20, shutil.get_terminal_size((80, 20)).columns - 1)
        text = message if len(message) <= width else "..." + message[-(width - 3) :]
        sys.stderr.write("\r" + text.ljust(width))
        sys.stderr.flush()
        self._shown = True

    def clear(self) -> None:
        if self._shown:
            width = max(20, shutil.get_terminal_size((80, 20)).columns - 1)
            sys.stderr.write("\r" + " " * width + "\r")
            sys.stderr.flush()
            self._shown = False


# ------------------------------------------------------------------------ scan


def _apply_scan_overrides(args: argparse.Namespace, settings: Settings) -> None:
    if args.workers is not None:
        settings.workers = args.workers
    if args.exclude:
        settings.exclude = [*settings.exclude, *args.exclude]
    if args.max_file_size is not None:
        settings.limits.max_file_size = parse_size(args.max_file_size)
    if args.no_archives:
        settings.scan_archives = False
    if args.follow_symlinks:
        settings.follow_symlinks = True
    if args.include_offline:
        settings.include_offline = True
    validate(settings)


def _engine_line(report: ScanReport) -> str:
    parts = []
    for info in report.engines:
        if info.available:
            detail = " ".join(
                x for x in (info.version, f"({info.detail})" if info.detail else "") if x
            )
            parts.append(f"{info.name} {detail}".strip())
        else:
            parts.append(f"{info.name}: {info.detail or 'not available'}")
    return "Engines: " + " | ".join(parts)


def _print_report(report: ScanReport, *, verbose: bool, quiet: bool) -> None:
    if not quiet:
        print(_engine_line(report))
        for notice in report.notices:
            print(f"! {notice}")
        print()

    if report.findings:
        print(f"THREATS FOUND ({len(report.findings)})")
        for finding in report.findings:
            print(f"  [{str(finding.severity).upper():<8}] {finding.location}")
            for d in finding.detections:
                extra = f"  [{d.source}]" if d.source else ""
                desc = f" - {d.description}" if d.description and verbose else ""
                print(f"               {d.engine:<7} {d.name}{extra}{desc}")
        print()

    if report.issues:
        print(f"NOT FULLY SCANNED ({len(report.issues)})")
        shown = report.issues if verbose else report.issues[:MAX_ISSUES_SHOWN]
        for issue in shown:
            print(f"  {issue.kind!s:<14} {issue.location}: {issue.message}")
        hidden = len(report.issues) - len(shown)
        if hidden:
            print(f"  ... and {hidden} more (use --verbose or --report FILE for the full list)")
        print()

    stats = report.stats
    if not quiet:
        print(
            f"Scanned {stats.files_scanned:,} files ({format_size(stats.bytes_scanned)}), "
            f"{stats.members_scanned:,} archive members in {report.duration_seconds:.1f}s"
        )
        skipped = {
            "excluded": stats.excluded,
            "links": stats.links_skipped,
            "special files": stats.special_skipped,
            "cloud-only": stats.offline_skipped,
            "vanished during scan": stats.vanished,
        }
        listed = ", ".join(f"{count:,} {label}" for label, count in skipped.items() if count)
        if listed:
            print(f"Skipped by policy: {listed}")
    print("Result: " + _verdict(report))


def _verdict(report: ScanReport) -> str:
    parts = []
    if report.cancelled:
        parts.append("CANCELLED - results are partial")
    if report.findings:
        parts.append(f"{len(report.findings)} threat(s) found")
    elif not report.cancelled:
        parts.append("no threats found")
    if report.issues:
        parts.append(f"scan incomplete ({len(report.issues)} item(s) not fully scanned)")
    return "; ".join(parts)


def _exit_code(report: ScanReport) -> int:
    if report.cancelled:
        return EXIT_CANCELLED
    if report.findings:
        return EXIT_THREATS
    if report.issues:
        return EXIT_INCOMPLETE
    return EXIT_CLEAN


def _quarantine_findings(report: ScanReport, settings: Settings, args: argparse.Namespace) -> int:
    say = _err if args.json else print
    targets: dict[str, tuple[str | None, list[Detection], bool]] = {}
    for finding in report.findings:
        sha, detections, in_archive = targets.get(finding.path, (finding.sha256, [], False))
        targets[finding.path] = (
            sha,
            [*detections, *finding.detections],
            in_archive or bool(finding.member),
        )

    if not args.yes and not sys.stdin.isatty():
        _err("Not quarantining: confirmation is required. Re-run with --yes to quarantine all.")
        return 0
    store = QuarantineStore(settings.quarantine_dir)
    approve_all = args.yes
    failures = 0
    say("")
    for path, (sha, detections, in_archive) in targets.items():
        if not approve_all:
            note = " (archive containing a detected item)" if in_archive else ""
            answer = input(f"Quarantine {path}{note}? [y]es/[N]o/[a]ll/[q]uit: ").strip().lower()
            if answer in ("q", "quit"):
                break
            if answer in ("a", "all"):
                approve_all = True
            elif answer not in ("y", "yes"):
                continue
        try:
            entry = store.add(path, expected_sha256=sha, detections=detections)
        except QuarantineError as exc:
            failures += 1
            _err(f"  FAILED: {exc}")
            continue
        say(f"  Quarantined {path} (id {entry.id})")
    return failures


def cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    _apply_scan_overrides(args, settings)
    if args.quarantine and args.json and not args.yes:
        _err("--quarantine with --json requires --yes (prompts would corrupt the JSON output)")
        return EXIT_USAGE
    runtime = build_runtime(settings, use_clamav=not args.no_clamav)
    scanner = Scanner(settings, runtime.engines, runtime.infos, runtime.notices)
    progress = _ProgressLine() if sys.stderr.isatty() and not (args.json or args.quiet) else None
    try:
        report = scanner.scan(args.paths, progress=progress)
    finally:
        if progress:
            progress.clear()
        runtime.close()

    if args.report:
        Path(args.report).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_report(report, verbose=args.verbose, quiet=args.quiet)
        if args.report:
            print(f"Full report written to {args.report}")

    if args.quarantine and report.findings and not report.cancelled:
        failures = _quarantine_findings(report, settings, args)
        if failures:
            _err(f"{failures} item(s) could not be quarantined.")
    return _exit_code(report)


# ------------------------------------------------------------------ quarantine


def cmd_quarantine(args: argparse.Namespace, settings: Settings) -> int:
    store = QuarantineStore(settings.quarantine_dir)
    try:
        if args.action == "list":
            entries = store.list()
            if args.json:
                print(json.dumps([e.to_public_dict() for e in entries], indent=2))
            elif not entries:
                print(f"Quarantine is empty ({store.root}).")
            else:
                print(f"{'ID':<27} {'QUARANTINED':<26} {'SIZE':>10}  DETECTION / ORIGINAL PATH")
                for e in entries:
                    print(
                        f"{e.id:<27} {e.quarantined_at:<26} {format_size(e.size):>10}  {e.summary}"
                    )
                    print(f"{'':<66}{e.original_path}")
            return EXIT_CLEAN
        if args.action == "restore":
            target = store.restore(args.id, args.to, overwrite=args.overwrite)
            print(
                f"Restored to {target}. Venom will detect it again on the next scan unless the "
                "detection was a false positive that you have excluded."
            )
            return EXIT_CLEAN
        if args.action == "delete":
            entry = store.get(args.id)
            if not args.yes:
                if not sys.stdin.isatty():
                    _err("Confirmation required; re-run with --yes.")
                    return EXIT_USAGE
                prompt = f"Permanently delete {entry.original_path} ({entry.id})? [y/N]: "
                if input(prompt).strip().lower() not in ("y", "yes"):
                    print("Nothing deleted.")
                    return EXIT_CLEAN
            store.delete(entry.id)
            print(f"Permanently deleted {entry.id}.")
            return EXIT_CLEAN
    except QuarantineError as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    return EXIT_USAGE


# --------------------------------------------------------------------- update


def cmd_update(args: argparse.Namespace, settings: Settings) -> int:
    if args.rollback:
        result = rollback_feed(settings, args.rollback)
        print(f"{result.name}: {result.status} - {result.message}")
        return EXIT_CLEAN if result.ok else EXIT_ERROR

    known = {feed.name: feed for feed in settings.feeds}
    unknown = [name for name in args.feed or [] if name not in known]
    if unknown:
        _err(f"unknown feed(s): {', '.join(unknown)}. Configured: {', '.join(known) or 'none'}")
        return EXIT_USAGE
    feeds = [known[n] for n in args.feed] if args.feed else [f for f in settings.feeds if f.enabled]

    results = []
    for feed in feeds:
        print(f"Updating rule feed {feed.name} ...", flush=True)
        result = update_feed(settings, feed, allow_downgrade=args.allow_downgrade)
        print(f"  {result.status}: {result.message}")
        results.append(result)
    if any(r.status in ("updated", "rolled-back") for r in results):
        compiled = load_rules(collect(settings).yara, settings.cache_dir)
        print(f"Compiled {compiled.rule_count} YARA rules.")
        for error in compiled.errors:
            print(f"  ! skipped: {error}")
    if not args.no_clamav:
        print("Updating ClamAV signatures (freshclam) ...", flush=True)
        result = run_freshclam(settings)
        print(f"  {result.status}: {result.message}")
        results.append(result)
    return EXIT_CLEAN if all(r.ok for r in results) else EXIT_ERROR


# --------------------------------------------------------------------- status


def _status_data(settings: Settings) -> dict[str, Any]:
    runtime = build_runtime(settings)
    feeds = []
    for feed in settings.feeds:
        state = read_feed_state(feed_current_dir(settings, feed.name))
        age = feed_age_days(state) if state else None
        feeds.append(
            {
                "name": feed.name,
                "enabled": feed.enabled,
                "url": feed.url,
                "installed": state is not None,
                "fetched_at": state.get("fetched_at") if state else None,
                "age_days": round(age, 1) if age is not None else None,
                "rule_count": state.get("rule_count") if state else None,
                "trust": state.get("trust") if state else None,
                "version": state.get("version") if state else None,
                "rollback_available": (settings.feeds_dir / feed.name / "previous").is_dir(),
            }
        )
    data = {
        "version": __version__,
        "config_path": str(settings.config_path),
        "config_exists": settings.config_path.is_file(),
        "data_dir": str(settings.data_dir),
        "rules_dir": str(settings.rules_dir),
        "user_rule_files": len(rule_files(settings.rules_dir)),
        "engines": [info.to_dict() for info in runtime.infos],
        "feeds": feeds,
        "quarantine_items": len(QuarantineStore(settings.quarantine_dir).list()),
        "notices": runtime.notices,
    }
    runtime.close()
    return data


def cmd_status(args: argparse.Namespace, settings: Settings) -> int:
    data = _status_data(settings)
    if args.json:
        print(json.dumps(data, indent=2))
        return EXIT_CLEAN
    print(f"Venom {data['version']}")
    exists = "" if data["config_exists"] else " (not created; defaults in use)"
    print(f"Config:      {data['config_path']}{exists}")
    print(f"Data:        {data['data_dir']}")
    print(f"User rules:  {data['rules_dir']} ({data['user_rule_files']} file(s))")
    print(f"Quarantine:  {data['quarantine_items']} item(s)")
    print("Engines:")
    for e in data["engines"]:
        state = "available" if e["available"] else "NOT AVAILABLE"
        version = e["version"] or "-"
        print(f"  {e['name']:<7} {state:<14} {version:<8} {e['detail']}".rstrip())
    print("Rule feeds:")
    for f in data["feeds"]:
        if not f["enabled"]:
            print(f"  {f['name']:<20} disabled")
        elif not f["installed"]:
            print(f"  {f['name']:<20} not installed (run `venom update`)")
        else:
            print(
                f"  {f['name']:<20} {f['rule_count']} rules, updated {f['fetched_at']} "
                f"({f['age_days']} days ago), {f['trust']}"
            )
    for notice in data["notices"]:
        print(f"! {notice}")
    return EXIT_CLEAN


# ---------------------------------------------------------------------- rules


def cmd_rules_check(args: argparse.Namespace, settings: Settings) -> int:
    paths = [Path(p) for p in args.paths] if args.paths else [settings.rules_dir]
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(rule_files(path))
        elif args.paths:
            files.append(path)
    if not files:
        print(f"No rule files found in {', '.join(map(str, paths))}.")
        return EXIT_CLEAN
    failed = 0
    from venom.engines.hashes import HashListError, parse_hash_list

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() == HASH_SUFFIX:
                count = len(parse_hash_list(text, str(path)))
                print(f"  OK    {path} ({count} hashes)")
                continue
            compiled = compile_sources([RuleSource("check", str(path), text)])
            if compiled.errors:
                raise ValueError(compiled.errors[0])
            print(f"  OK    {path} ({compiled.rule_count} rules)")
        except (OSError, ValueError, HashListError) as exc:
            failed += 1
            print(f"  ERROR {exc}")
    return EXIT_ERROR if failed else EXIT_CLEAN


# --------------------------------------------------------------------- bundle


def cmd_bundle(args: argparse.Namespace, settings: Settings) -> int:
    try:
        if args.action == "keygen":
            key_path, public_key = generate_keypair(Path(args.out))
            print(f"Private key: {key_path}  (keep it secret; never commit it)")
            print(f"Public key:  {public_key}")
            print("\nClients trust bundles signed with this key via config.toml:\n")
            print('[[feeds]]\nname = "my-rules"\nurl = "https://example.org/venom-rules.zip"')
            print(f'public_key = "{public_key}"')
            return EXIT_CLEAN
        if args.action == "create":
            sig = create_bundle(Path(args.rules_dir), Path(args.out), args.version, Path(args.key))
            print(f"Wrote {args.out} and {sig}. Publish both at the same URL prefix.")
            return EXIT_CLEAN
    except BundleError as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    return EXIT_USAGE


# --------------------------------------------------------------------- config


def cmd_config(args: argparse.Namespace, settings: Settings) -> int:
    if args.action == "path":
        print(settings.config_path)
    elif args.action == "init":
        path = settings.config_path
        if path.exists() and not args.force:
            _err(f"{path} already exists (use --force to overwrite)")
            return EXIT_ERROR
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        print(f"Wrote {path}")
    elif args.action == "show":
        data = {
            "config_path": str(settings.config_path),
            "data_dir": str(settings.data_dir),
            "rules_dir": str(settings.rules_dir),
            "workers": settings.workers,
            "follow_symlinks": settings.follow_symlinks,
            "include_offline": settings.include_offline,
            "scan_archives": settings.scan_archives,
            "exclude": settings.exclude,
            "limits": settings.limits.__dict__,
            "clamav": settings.clamav.__dict__,
            "feeds": [f.__dict__ for f in settings.feeds],
        }
        print(json.dumps(data, indent=2))
    return EXIT_CLEAN


def cmd_selftest(args: argparse.Namespace, settings: Settings) -> int:
    return EXIT_CLEAN if run_selftest(settings, print) else EXIT_ERROR


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="venom",
        description="Open-source, cross-platform malware scanner (YARA-X + ClamAV).",
        epilog="Exit codes: 0 clean, 1 threats found, 2 usage error, 3 scan incomplete, "
        "4 error, 130 cancelled.",
    )
    parser.add_argument("--version", action="version", version=f"venom {__version__}")
    parser.add_argument("--config", metavar="PATH", help="configuration file to use")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="scan files and directories")
    scan.add_argument("paths", nargs="+", metavar="PATH")
    scan.add_argument("--json", action="store_true", help="print the full report as JSON")
    scan.add_argument("--report", metavar="FILE", help="also write the JSON report to FILE")
    scan.add_argument(
        "--quarantine", action="store_true", help="offer to quarantine detected files"
    )
    scan.add_argument("-y", "--yes", action="store_true", help="quarantine without prompting")
    scan.add_argument("--workers", type=int, metavar="N", help="parallel file workers")
    scan.add_argument("--exclude", action="append", metavar="GLOB", help="exclude matching paths")
    scan.add_argument("--max-file-size", metavar="SIZE", help="e.g. 512M; 0 = unlimited")
    scan.add_argument("--no-archives", action="store_true", help="do not look inside archives")
    scan.add_argument("--no-clamav", action="store_true", help="skip ClamAV for this scan")
    scan.add_argument("--follow-symlinks", action="store_true", help="follow links while walking")
    scan.add_argument(
        "--include-offline",
        action="store_true",
        help="scan cloud-only placeholders (downloads them)",
    )
    scan.add_argument(
        "-v", "--verbose", action="store_true", help="show every issue and rule description"
    )
    scan.add_argument(
        "-q", "--quiet", action="store_true", help="only print threats, issues and the result"
    )
    scan.set_defaults(func=cmd_scan)

    quarantine = sub.add_parser("quarantine", help="list, restore or delete quarantined files")
    qsub = quarantine.add_subparsers(dest="action", metavar="ACTION", required=True)
    qlist = qsub.add_parser("list", help="list quarantined files")
    qlist.add_argument("--json", action="store_true")
    qrestore = qsub.add_parser("restore", help="restore a file after integrity verification")
    qrestore.add_argument("id", help="quarantine id (a unique prefix is enough)")
    qrestore.add_argument(
        "--to", metavar="PATH", help="restore somewhere other than the original path"
    )
    qrestore.add_argument("--overwrite", action="store_true", help="replace an existing file")
    qdelete = qsub.add_parser("delete", help="permanently delete a quarantined file")
    qdelete.add_argument("id")
    qdelete.add_argument("-y", "--yes", action="store_true")
    quarantine.set_defaults(func=cmd_quarantine)

    update = sub.add_parser("update", help="update rule feeds and ClamAV signatures")
    update.add_argument("--feed", action="append", metavar="NAME", help="only update this feed")
    update.add_argument("--no-clamav", action="store_true", help="skip running freshclam")
    update.add_argument("--rollback", metavar="NAME", help="restore a feed's previous rules")
    update.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="accept a signed bundle older than the installed one",
    )
    update.set_defaults(func=cmd_update)

    status = sub.add_parser("status", help="show engines, rule feeds and quarantine state")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    rules = sub.add_parser("rules", help="work with custom rules")
    rsub = rules.add_subparsers(dest="action", metavar="ACTION", required=True)
    rcheck = rsub.add_parser("check", help="validate YARA and hash-list files")
    rcheck.add_argument("paths", nargs="*", metavar="PATH")
    rcheck.set_defaults(func=cmd_rules_check)

    bundle = sub.add_parser("bundle", help="create signed rule bundles (for rule publishers)")
    bsub = bundle.add_subparsers(dest="action", metavar="ACTION", required=True)
    keygen = bsub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    keygen.add_argument("--out", required=True, metavar="DIR")
    create = bsub.add_parser("create", help="validate, package and sign a rules directory")
    create.add_argument("rules_dir", metavar="RULES_DIR")
    create.add_argument("--version", type=int, required=True, help="monotonically increasing")
    create.add_argument("--key", required=True, metavar="KEY", help="private key from keygen")
    create.add_argument("--out", required=True, metavar="FILE")
    bundle.set_defaults(func=cmd_bundle)

    config = sub.add_parser("config", help="show or create the configuration file")
    config.add_argument("action", choices=["path", "show", "init"])
    config.add_argument("--force", action="store_true", help="overwrite with init")
    config.set_defaults(func=cmd_config)

    selftest = sub.add_parser(
        "selftest", help="verify detection, archives and quarantine end to end"
    )
    selftest.set_defaults(func=cmd_selftest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        settings = load_settings(Path(args.config) if args.config else None)
        return args.func(args, settings)
    except ConfigError as exc:
        _err(f"configuration error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("\ninterrupted")
        return EXIT_CANCELLED
