# Collection Guide

This guide describes what Junosleuth collects, which features control each evidence source, and where the resulting artifacts are written.

Junosleuth is a collection tool. It preserves router state, command output, metadata, selected files, and optional memory artifacts so analysis can happen offline. It does not classify artifacts as malicious during acquisition and it does not perform remediation.

## Collection sequence

A typical acquisition can include:

1. SSH landing-mode detection
2. login-notice learning
3. run-manifest creation
4. platform fingerprinting
5. baseline Junos CLI collection
6. optional Juniper Malware Removal Tool collection
7. optional OS-shell collection
8. optional filesystem metadata and file acquisition
9. optional existing-core acquisition
10. optional targeted live-memory acquisition
11. final evidence hashing

Preserve volatile evidence before rebooting, upgrading, cleaning, restarting services, or otherwise modifying the device whenever circumstances permit.

## SSH and output handling

Junosleuth first determines whether the SSH account lands directly in the Junos CLI or in an OS shell. The detected mode is recorded in `meta/manifest.txt` as `remote_mode=cli` or `remote_mode=shell`.

For each command, Junosleuth stores two forms of output:

| Location | Purpose |
|---|---|
| `raw/cli/*.raw.txt` | original stdout from Junos CLI commands |
| `raw/shell/*.raw.txt` | original stdout from OS-shell commands |
| `cli/*.txt` | analyst-facing Junos CLI output |
| `shell/*.txt` | analyst-facing OS-shell output |

The analyst-facing files remove only the learned repeated login notice. Raw files remain unchanged so the package keeps a copy of the original SSH stdout.

Each analyst-facing command output ends with collection metadata, including:

| Field | Meaning |
|---|---|
| `collected_utc` | UTC time when the command output was written |
| `command` or `shell_command` | remote command that was executed |
| `remote_mode` | SSH landing mode used for the command |
| `raw_output` | matching raw stdout path |
| `exit_status` | SSH or remote command exit status |
| `semantic_status` | best-effort status such as `ok`, `command_error`, `remote_error`, or `transport_error` |
| `ssh_attempts` | number of SSH attempts used for the command |

Repeated SSH stderr is retained in `meta/ssh_stderr.log` when present.

SSH landing-mode probes are retained under `meta/probe_direct.*` and `meta/probe_shell.*`. The Bash collector also retains `meta/banner_probe_a.*` and `meta/banner_probe_b.*` from login-notice learning.

## Baseline Junos CLI collection

Baseline Junos CLI collection runs by default. It captures platform identity, Routing Engine state, network state, configuration state, logs, and file listings through operational Junos commands.

### Platform and identity

| Output | Evidence |
|---|---|
| `cli/00_platform_version.txt` | Junos version and platform family detection source |
| `cli/01_show_chassis_hardware_detail.txt` | chassis, modules, serials, and hardware inventory |
| `cli/02_show_system_uptime.txt` | uptime and boot timing context |
| `cli/03_show_system_users.txt` | logged-in users visible to Junos |
| `cli/04_show_system_alarms.txt` | active system alarms |
| `cli/05_show_chassis_alarms.txt` | active chassis alarms |
| `cli/06_show_system_storage.txt` | filesystem usage from Junos |
| `cli/07_show_system_core_dumps.txt` | Junos-visible core dump inventory |
| `cli/08_show_chassis_routing_engine.txt` | Routing Engine health and status |
| `cli/09_show_system_memory.txt` | memory state reported by Junos |

### Volatile Routing Engine state

| Output | Evidence |
|---|---|
| `cli/10_show_system_processes_extensive.txt` | process table and process resource usage |
| `cli/11_show_system_connections.txt` | active connections reported by Junos |
| `cli/12_show_system_connections_extensive.txt` | extended connection detail where supported |
| `cli/13_show_system_statistics.txt` | system statistics |
| `cli/14_show_task_memory.txt` | Junos task memory information |

`12_show_system_connections_extensive.txt` is collected only on traditional Junos platforms where the command is expected to be relevant.

### Network and routing state

| Output | Evidence |
|---|---|
| `cli/20_show_interfaces_terse.txt` | compact interface state |
| `cli/21_show_interfaces_extensive.txt` | detailed interface counters and state |
| `cli/22_show_route_summary.txt` | routing table summary |
| `cli/23_show_forwarding_table_summary.txt` | forwarding table summary |
| `cli/24_show_arp_no_resolve.txt` | ARP entries without name resolution |
| `cli/25_show_bgp_summary.txt` | BGP session summary |

### Configuration, logs, and Junos file listings

| Output | Evidence |
|---|---|
| `cli/30_show_system_commit.txt` | commit history visible through Junos |
| `cli/31_configuration_display_set.txt` | configuration in `display set` form |
| `cli/40_log_messages.txt` | Junos messages log |
| `cli/41_log_interactive_commands.txt` | interactive command log |
| `cli/42_log_authorization.txt` | authorization log |
| `cli/43_file_list_var_log.txt` | `/var/log` listing through Junos |
| `cli/44_file_list_var_tmp.txt` | `/var/tmp` listing through Junos |
| `cli/45_file_list_tmp.txt` | `/tmp` listing through Junos |

## Optional JMRT collection

Enable with `--jmrt` or `-RunJMRT`.

JMRT is the Juniper Malware Removal Tool, exposed on supported platforms through `request system malware-scan`. Junosleuth records JMRT output as evidence by running:

```text
request system malware-scan quick-scan clean-action warn
request system malware-scan integrity-check
```

The quick scan checks running processes and related executables for known malware signatures. When the executable is unavailable, the Juniper tool may inspect process memory instead. The integrity check reports whether Junos integrity mechanisms are enabled and working.

Junosleuth uses `clean-action warn` so JMRT reports findings without deleting files or stopping processes. This keeps the JMRT step aligned with evidence preservation rather than remediation.

| Output | Evidence |
|---|---|
| `cli/50_jmrt_quick_scan_warn.txt` | warn-only malware-scan quick-scan output |
| `cli/51_jmrt_integrity_check.txt` | integrity-check output |
| `raw/cli/50_jmrt_quick_scan_warn.raw.txt` | original quick-scan stdout |
| `raw/cli/51_jmrt_integrity_check.raw.txt` | original integrity-check stdout |

A negative JMRT result is not proof that the router is clean. Treat it as one evidence source among logs, process state, filesystem artifacts, memory evidence, and external telemetry.

## Optional OS-shell collection

Enable with `--shell` or `-RunShell`. Targeted memory acquisition also enables shell collection because `/proc` and memory reads require OS-shell access.

OS-shell collection captures host-level state that is not always visible through Junos operational commands. Command availability varies between Junos OS, Junos OS Evolved, hardware families, releases, and account permissions.

| Output | Evidence |
|---|---|
| `shell/60_uname.txt` | OS kernel and platform identity |
| `shell/61_date_utc.txt` | remote UTC time source |
| `shell/62_uptime.txt` | OS-level uptime |
| `shell/63_ps_auxww.txt` | process list with full arguments where available |
| `shell/64_ss_anp.txt` | Linux socket state on Junos OS Evolved |
| `shell/64_netstat_an.txt` | traditional Junos socket state |
| `shell/65_ip_addr.txt` | Linux interface address state on Junos OS Evolved |
| `shell/65_sockstat.txt` | traditional Junos socket ownership where available |
| `shell/66_mount.txt` | mounted filesystems |
| `shell/67_df_h.txt` | filesystem usage from the shell |
| `shell/68_writable_dirs_listing.txt` | detailed listing of common writable directories |
| `shell/69_writable_files_find.txt` | file inventory under common writable directories |
| `shell/70_logged_in_users.txt` | OS-level logged-in user evidence |
| `shell/71_process_provenance.txt` | process parent, owner, start time, and arguments where available |
| `shell/72_proc_metadata_index.txt` | readable `/proc` metadata path index |
| `shell/73_proc_metadata.txt` | collected `/proc` status, command line, maps, and related links where readable |

The `64_*` and `65_*` outputs are platform dependent. A run normally contains either the Junos OS Evolved pair or the traditional Junos pair, not both.

## Optional file acquisition

Enable with `--acquire-files` or `-AcquireFiles`.

File acquisition is intended for selected evidence, not full disk imaging. Junosleuth first records remote metadata and candidate paths, then copies selected files to the workstation with their remote path mirrored under `files/`.

For example, `/var/log/messages` is stored as `files/var/log/messages`.

### Main forensic locations

| Location | Purpose |
|---|---|
| `/var/log/` | system, authentication, and operational logs |
| `/var/tmp/` | temporary files and common staging location |
| `/tmp/` | temporary files and common staging location |
| `/var/core/` | existing core evidence |
| `/var/crash/` | existing crash evidence |
| `/var/core/re/`, `/var/core/re0/`, `/var/core/re1/` | Routing Engine core evidence on some platforms |
| `/config/` | configuration database and local configuration artifacts |
| `/var/db/config/` | configuration history and database artifacts |
| `/var/rundb+` | runtime or configuration database evidence |
| `/mfs/var/etc/` | Junos and OS configuration artifacts |
| `/root/` | administrative artifacts where accessible |
| `/home/` | user artifacts where accessible |
| `/usr/lib/libjucomm.so.1` | priority library artifact when present |

### Priority files

Junosleuth always attempts these priority files when file acquisition is enabled:

```text
/var/log/messages
/var/log/interactive-commands
/var/log/authorization
/mfs/var/etc/syslog.conf
/mfs/var/etc/syslog.conf0
/var/rundb+
/config/usage_db
/var/db/config/usage_db
/usr/lib/libjucomm.so.1
```

It then attempts additional discovered files from the main forensic locations. Generic non-core artifacts are size-limited to reduce production impact and workstation storage risk. Existing core files are handled separately because they can legitimately be large.

### Metadata and integrity records

| Output | Evidence |
|---|---|
| `meta/remote_file_metadata.txt` | remote file path, type, size, owner, group, mode, inode, mtime, ctime, and atime where available |
| `meta/remote_file_metadata.stderr` | stderr from remote metadata collection |
| `meta/remote_file_candidates.txt` | discovered candidate paths for acquisition |
| `meta/acquired_files_manifest.txt` | acquisition result for each attempted file |
| `meta/file_acquisition.log` | local SCP transfer log |

For acquired files, `meta/acquired_files_manifest.txt` records:

| Field | Meaning |
|---|---|
| `remote_path` | original path on the router |
| `local_path` | path inside the evidence package |
| `status` | `acquired` or `failed` |
| `remote_size` | remote file size when available |
| `local_size` | copied file size when acquired |
| `remote_sha256` | remote SHA-256 when available |
| `local_sha256` | workstation SHA-256 when acquired |
| `hash_match` | whether remote and local hashes matched when both were available |

Remote and local SHA-256 values verify transfer integrity. They are not IOC checks.

## Existing core dump acquisition

Existing core and crash files are valuable historical memory evidence. When file acquisition is enabled, Junosleuth discovers and attempts to acquire cores from:

```text
/var/core
/var/crash
/var/tmp/*.core
/var/tmp/*.core.*
/var/tmp/core.*
/var/tmp/*core*.tgz
```

Discovery output is retained in:

| Output | Evidence |
|---|---|
| `meta/existing_core_candidates.txt` | discovered core and crash candidate paths |
| `meta/existing_core_candidates.stderr` | stderr from core discovery |

Core files are copied under `files/` using the same mirrored-path convention as other acquired files.

## Experimental targeted live-memory acquisition

Enable with `--acquire-memory <pid[,pid]>` or `-AcquireMemory "<pid[,pid]>"`.

Targeted live-memory acquisition is explicit and experimental. It reads readable mapped regions from `/proc/<pid>/mem` and streams bounded chunks directly to the forensic workstation. It does not suspend the target process, does not stage memory data on the router, and does not require Python, Perl, or Ruby on the router.

Before memory reads, Junosleuth records health context:

| Output | Evidence |
|---|---|
| `cli/80_memory_pre_routing_engine.txt` | Routing Engine state before memory acquisition |
| `cli/81_memory_pre_processes.txt` | process state before memory acquisition |
| `cli/82_memory_pre_storage.txt` | storage state before memory acquisition |
| `cli/83_memory_pre_system_memory.txt` | memory state before memory acquisition |

After memory reads, it records the same categories again:

| Output | Evidence |
|---|---|
| `cli/84_memory_post_routing_engine.txt` | Routing Engine state after memory acquisition |
| `cli/85_memory_post_processes.txt` | process state after memory acquisition |
| `cli/86_memory_post_storage.txt` | storage state after memory acquisition |
| `cli/87_memory_post_system_memory.txt` | memory state after memory acquisition |

Each requested PID gets its own directory:

```text
memory/<pid>/
|-- manifest.txt
|-- process_identity.txt
|-- process_identity.stderr
|-- map_before.txt
|-- map.stderr
|-- map_after.txt
|-- map_after.stderr
+-- regions/
    |-- <start>-<end>.bin
    +-- <start>-<end>.stderr
```

`process_identity.stderr` is retained by the Bash collector when present. PowerShell records the process identity stdout in `process_identity.txt`.

The per-PID manifest records the PID, start and finish times, configured rate limit, region ranges, expected and actual byte counts, permissions, status, SHA-256, and backing path where available.

Memory acquisition is a rolling view, not an atomic snapshot. The process continues running while regions are read, so mappings and content can change during collection. Compare `map_before.txt`, `map_after.txt`, the per-region status, and the pre/post Routing Engine health files during analysis.

## Run metadata and final hashing

`meta/manifest.txt` records run-level settings and context, including target, SSH user, UTC start and finish times, platform family, remote mode, enabled options, memory rate, recommended file paths, and recommended priority files.

`meta/collector.log` records collection progress on the workstation. Probe files and login-notice files document SSH landing-mode detection and banner handling.

At the end of collection, Junosleuth writes `SHA256SUMS.txt` at the evidence package root. It covers files under `cli/`, `shell/`, `raw/`, `files/`, `memory/`, and `meta/`.

## Evidence layout

The exact package contents depend on selected options, platform support, command support, permissions, and whether matching files exist on the router.

```text
<device>_<utc-timestamp>/
|-- cli/
|   |-- 00_platform_version.txt
|   |-- 01_show_chassis_hardware_detail.txt
|   |-- 10_show_system_processes_extensive.txt
|   |-- 20_show_interfaces_terse.txt
|   |-- 31_configuration_display_set.txt
|   |-- 40_log_messages.txt
|   |-- 50_jmrt_quick_scan_warn.txt
|   |-- 51_jmrt_integrity_check.txt
|   |-- 80_memory_pre_routing_engine.txt
|   +-- 87_memory_post_system_memory.txt
|-- shell/
|   |-- 60_uname.txt
|   |-- 63_ps_auxww.txt
|   |-- 64_netstat_an.txt
|   |-- 64_ss_anp.txt
|   |-- 65_sockstat.txt
|   |-- 65_ip_addr.txt
|   |-- 68_writable_dirs_listing.txt
|   +-- 73_proc_metadata.txt
|-- raw/
|   |-- cli/
|   |   |-- 00_platform_version.raw.txt
|   |   |-- 40_log_messages.raw.txt
|   |   +-- 50_jmrt_quick_scan_warn.raw.txt
|   +-- shell/
|       |-- 60_uname.raw.txt
|       +-- 73_proc_metadata.raw.txt
|-- files/
|   |-- var/
|   |   |-- log/
|   |   |   |-- messages
|   |   |   |-- interactive-commands
|   |   |   +-- authorization
|   |   |-- tmp/
|   |   |-- core/
|   |   +-- crash/
|   |-- config/
|   |-- mfs/
|   |   +-- var/
|   |       +-- etc/
|   |-- root/
|   |-- home/
|   +-- usr/
|       +-- lib/
|           +-- libjucomm.so.1
|-- memory/
|   +-- <pid>/
|       |-- manifest.txt
|       |-- process_identity.txt
|       |-- map_before.txt
|       |-- map_after.txt
|       +-- regions/
|           |-- <start>-<end>.bin
|           +-- <start>-<end>.stderr
|-- meta/
|   |-- manifest.txt
|   |-- collector.log
|   |-- login_notice.txt
|   |-- probe_direct.raw
|   |-- probe_direct.stderr
|   |-- probe_shell.raw
|   |-- probe_shell.stderr
|   |-- banner_probe_a.raw
|   |-- banner_probe_a.stderr
|   |-- banner_probe_b.raw
|   |-- banner_probe_b.stderr
|   |-- ssh_stderr.log
|   |-- remote_file_metadata.txt
|   |-- remote_file_metadata.stderr
|   |-- remote_file_candidates.txt
|   |-- acquired_files_manifest.txt
|   |-- file_acquisition.log
|   |-- existing_core_candidates.txt
|   +-- existing_core_candidates.stderr
+-- SHA256SUMS.txt
```

## Recommended workflow

```text
External telemetry
       |
       v
Volatile Junos state
       |
       v
OS/process/socket state
       |
       v
Filesystem metadata
       |
       v
Selective file/core acquisition
       |
       v
Optional targeted memory
       |
       v
Evidence hashing
       |
       v
Offline analysis
       |
       v
Containment/remediation
```

## Collection versus analysis

Junosleuth intentionally does not treat a known filename, hash, port, process, or address as proof of compromise. Offline tooling can subsequently perform IOC matching, timelines, YARA, configuration comparison, process/socket correlation, log-gap analysis, and malware analysis.
