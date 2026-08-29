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
<device>_<utc-timestamp>/
|-- cli/
|   |-- 00_platform_version.txt
|   |-- 01_show_chassis_hardware_detail.txt
|   |-- 10_show_system_processes_extensive.txt
|   |-- 20_show_interfaces_terse.txt
|   |-- 31_configuration_display_set.txt
|   |-- 40_log_messages.txt
|   `-- 50_jmrt_quick_scan_warn.txt
|-- shell/
|   |-- 60_uname.txt
|   |-- 63_ps_auxww.txt
|   |-- 64_netstat_an.txt
|   |-- 68_writable_dirs_listing.txt
|   `-- 73_proc_metadata.txt
|-- raw/
|   |-- cli/
|   |   |-- 00_platform_version.raw.txt
|   |   `-- 40_log_messages.raw.txt
|   `-- shell/
|       |-- 60_uname.raw.txt
|       `-- 73_proc_metadata.raw.txt
|-- files/
|   |-- var/
|   |   |-- log/
|   |   |   |-- messages
|   |   |   |-- interactive-commands
|   |   |   `-- authorization
|   |   |-- tmp/
|   |   |-- core/
|   |   `-- crash/
|   |-- config/
|   |-- mfs/
|   |   `-- var/
|   |       `-- etc/
|   |-- root/
|   |-- home/
|   `-- usr/
|       `-- lib/
|           `-- libjucomm.so.1
|-- memory/
|   `-- <pid>/
|       |-- manifest.txt
|       |-- process_identity.txt
|       |-- map_before.txt
|       |-- map_after.txt
|       `-- regions/
|           |-- <start>-<end>.bin
|           `-- <start>-<end>.stderr
|-- meta/
|   |-- manifest.txt
|   |-- collector.log
|   |-- login_notice.txt
|   |-- ssh_stderr.log
|   |-- remote_file_metadata.txt
|   |-- remote_file_metadata.stderr
|   |-- remote_file_candidates.txt
|   |-- acquired_files_manifest.txt
|   |-- file_acquisition.log
|   |-- existing_core_candidates.txt
|   `-- existing_core_candidates.stderr
`-- SHA256SUMS.txt
```

The `cli/` and `shell/` files are analyst-facing copies. Each file includes collection metadata such as command, remote mode, raw-output path, exit status, semantic status, and SSH-attempt count. The `raw/` tree preserves the original SSH stdout before cleanup.

The `files/` tree mirrors acquired remote paths below the evidence package root. For example, `/var/log/messages` is stored as `files/var/log/messages`.

The `memory/` tree is created when targeted live-memory acquisition is requested. Each PID gets its own directory, memory-map snapshots, process identity output, a per-PID manifest, and one binary file per acquired readable region.

The `meta/` tree contains run metadata, logs, probe output, file-acquisition records, remote filesystem inventory, and error output retained during best-effort collection. Some files and directories appear only when the corresponding option is enabled or the remote platform exposes the relevant data.

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

JMRT is the Juniper Malware Removal Tool, exposed on supported platforms through `request system malware-scan`. When enabled, Junosleuth records JMRT as an independent optional evidence source by running:

```text
request system malware-scan quick-scan clean-action warn
request system malware-scan integrity-check
```

The quick scan checks running processes and related executables for known malware signatures; when the executable is unavailable, the Juniper tool may inspect process memory instead. The integrity check reports whether Junos integrity mechanisms are enabled and working. Junosleuth uses `clean-action warn` so JMRT reports findings without deleting files or stopping processes.

## Collection versus analysis

Junosleuth intentionally does not treat a known filename, hash, port, process, or address as proof of compromise. Offline tooling can subsequently perform IOC matching, timelines, YARA, configuration comparison, process/socket correlation, log-gap analysis, and malware analysis.
