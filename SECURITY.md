# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/siPyt/venom/security/advisories/new),
not in public issues. Include the affected version, platform, reproduction steps, and the impact
you observed. We aim to acknowledge reports within 7 days and to coordinate disclosure after a fix
is available.

Do not attach live malware. If a sample is needed to reproduce a problem, share its SHA-256 hash
or a password-protected archive (password `infected`) only when we ask for it.

## Supported versions

Only the latest release receives security fixes while Venom is in the 0.x series.

## In scope

- Code execution, or reads and writes outside the expected locations, triggered by a scanned file,
  archive, rule feed, update bundle, or quarantine entry
- Bypasses of update authentication: TLS or redirect handling, SHA-256 pinning, Ed25519 signature
  verification, or downgrade protection
- Quarantine flaws: restoring altered content, path or symlink attacks during quarantine or
  restore, or quarantined files remaining executable
- Resource exhaustion that escapes the configured limits, such as archive bombs or oversized
  members
- Scanner evasion caused by a defect in Venom itself, such as files skipped silently instead of
  being reported as incomplete

## Out of scope

- Malware that the configured signature sources do not detect. Report missing detections to the
  rule or signature provider (YARA Forge, ClamAV, or the rule author), or open a normal issue.
- False positives. Open a normal issue.
- Attacks that require an attacker who already controls Venom’s configuration, data directory, or
  signing key
- Lack of real-time protection. Venom 0.x scans only on demand.

## Trust model

- **Scanned content is hostile.** Symlinks are not followed unless `--follow-symlinks` is given,
  only regular files are read, and archives are inspected in memory under hard per-file limits on
  depth, member count, member size, total size, and compression ratio. Nothing is extracted to
  disk, and scanned files are never executed.
- **Rule feeds are untrusted input until verified.** Downloads are HTTPS-only and size-capped.
  Feeds can be pinned by SHA-256 or signed with Ed25519 and given a monotonic version. Archive
  member names are never used as paths, and a new rule set must compile before activation.
- **Quarantine neutralizes content.** Quarantined files are XOR-encoded so they cannot run and are
  not picked up by other scanners. Restore verifies the original SHA-256 and never overwrites an
  existing file unless explicitly asked.
- **ClamAV is an external program.** Venom streams content to `clamd` or runs `clamscan` with
  arguments, never through a shell.
