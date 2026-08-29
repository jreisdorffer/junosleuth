# Collection Guide

## Collection sequence

A typical Junosleuth acquisition can include:

1. SSH landing-mode detection
2. platform fingerprinting
3. Junos CLI evidence
4. optional OS-shell evidence
5. filesystem metadata inventory
6. optional file and existing-core acquisition
7. optional targeted live-memory acquisition
8. evidence-package hashing

Preserve volatile evidence before rebooting, upgrading, cleaning, restarting services, or otherwise modifying the device whenever circumstances permit.

## Junos and OS evidence

Junosleuth collects platform/version, hardware, uptime, users, alarms, processes, Routing Engine connections, statistics, memory, interfaces, routing state, ARP, BGP, storage, core information, commit history, and configuration evidence where supported.

With `--shell` / `-RunShell`, it also attempts OS-level process, socket, user, mount, filesystem, and `/proc` evidence.

## Filesystem metadata

Before acquisition Junosleuth attempts to preserve `meta/remote_file_metadata.txt`, including available path, type, size, owner, group, permissions, inode, mtime, ctime, and atime information.

Failures are retained where possible.

## Main forensic locations

| Location | Purpose |
|---|---|
| `/var/log/` | system/authentication/operational logs |
| `/var/tmp/`, `/tmp/` | temporary and staging evidence |
| `/var/core/`, `/var/crash/` | existing core/crash evidence |
| `/config/`, `/var/db/config/` | configuration database/history |
| `/var/rundb+` | runtime/configuration database evidence |
| `/mfs/var/etc/` | Junos/OS configuration artifacts |
| `/root/`, `/home/` | user/administrative artifacts where accessible |

## File acquisition and integrity

Enable with `--acquire-files` or `-AcquireFiles`.

For acquired files Junosleuth attempts to record remote path, local path, remote SHA-256, local SHA-256, and hash-match status. These hashes verify transfer integrity; they are not IOC checks.

Existing core files are also discovered and may exceed the normal generic artifact-size limit.

## Evidence layout

```text
cli/       analyst-facing Junos output
shell/     OS-level evidence
raw/       unmodified SSH stdout
files/     acquired files/core dumps
memory/    targeted memory regions
meta/      manifests, metadata, logs and errors
SHA256SUMS.txt
```

## Recommended workflow

```text
External telemetry
       ↓
Volatile Junos state
       ↓
OS/process/socket state
       ↓
Filesystem metadata
       ↓
Selective file/core acquisition
       ↓
Optional targeted memory
       ↓
Evidence hashing
       ↓
Offline analysis
       ↓
Containment/remediation
```

JMRT can be included as an independent optional evidence source in warn/detection mode.

## Collection versus analysis

Junosleuth intentionally does not treat a known filename, hash, port, process, or address as proof of compromise. Offline tooling can subsequently perform IOC matching, timelines, YARA, configuration comparison, process/socket correlation, log-gap analysis, and malware analysis.
