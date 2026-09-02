<p align="center">
  <img src="assets/junosleuth-logo.png" alt="Junosleuth logo" width="550">
</p>

**Evidence-focused incident-response collection for Juniper Junos routers**

Junosleuth is a lightweight forensic collection toolkit for Junos devices. It preserves volatile system state, Routing Engine evidence, filesystem metadata, selected files, existing core dumps, and, when explicitly requested, targeted live process memory.

PowerShell and Bash collectors are provided for Windows and Unix-like forensic workstations.

> **Collect first. Analyze offline. Remediate deliberately.**

## Key capabilities

- Junos system, process, routing, interface, and connection state
- Direct Junos CLI and OS-shell SSH landing modes
- Raw SSH evidence plus analyst-friendly output
- Platform-aware FreeBSD/Linux shell collection
- Filesystem metadata and optional file acquisition
- Remote/local SHA-256 transfer verification
- Existing core-dump acquisition
- Best-effort `/proc` metadata and memory maps
- Experimental targeted live-memory acquisition by PID
- Optional Juniper Malware Removal Tool (JMRT) collection in warn/detection mode
- Final SHA-256 evidence manifest

JMRT is the Juniper Malware Removal Tool. When enabled, Junosleuth records Juniper malware-scan output as evidence and uses warn-only scanning so the collector does not attempt to remove detected files or stop processes.

## Quick start

### Bash

```bash
./junosleuth.sh -H 192.0.2.10 -u iruser -o /secure/evidence
```

By default, the Bash collector lets OpenSSH prompt for a password or key passphrase. Use `--batch` only for key-based unattended runs.

Full filesystem/OS collection:

```bash
./junosleuth.sh -H 192.0.2.10 -u iruser -o /secure/evidence --shell --acquire-files
```

Optional JMRT:

```bash
./junosleuth.sh -H 192.0.2.10 -u iruser -o /secure/evidence --jmrt
```

Experimental targeted memory:

```bash
./junosleuth.sh -H 192.0.2.10 -u iruser -o /secure/evidence --acquire-memory 1234 --memory-rate-mbps 5
```

### PowerShell

```powershell
.\junosleuth.ps1 -HostName 192.0.2.10 -UserName iruser -OutputBase C:\Evidence
```

By default, the PowerShell collector lets OpenSSH prompt for a password or key passphrase. Use `-BatchMode` only for key-based unattended runs.

Full filesystem/OS collection:

```powershell
.\junosleuth.ps1 -HostName 192.0.2.10 -UserName iruser -OutputBase C:\Evidence -RunShell -AcquireFiles
```

Optional JMRT:

```powershell
.\junosleuth.ps1 -HostName 192.0.2.10 -UserName iruser -OutputBase C:\Evidence -RunJMRT
```

Experimental targeted memory:

```powershell
.\junosleuth.ps1 -HostName 192.0.2.10 -UserName iruser -OutputBase C:\Evidence -AcquireMemory "1234" -MemoryRateMBps 5
```

## Evidence layout

```text
<device>_<timestamp>/
├── cli/
├── shell/
├── raw/
├── files/
├── memory/
├── meta/
└── SHA256SUMS.txt
```

Junosleuth preserves unsupported commands and collection failures where possible instead of silently discarding them.

## Collection philosophy

Junosleuth separates **collection** from **analysis**. It does not classify filenames, hashes, processes, ports, or connections as malicious during acquisition. IOC matching, timelines, YARA, process/socket correlation, and other analysis happen offline.

It also avoids intentional remediation such as rebooting, killing processes, deleting files, changing configuration, or cleaning malware.

## Documentation

Detailed material lives under [`docs/`](docs/):

- [`COLLECTION.md`](docs/COLLECTION.md): evidence scope, file acquisition, hashing, and workflow
- [`SSH-AND-PLATFORM.md`](docs/SSH-AND-PLATFORM.md): SSH landing modes, banners, raw output, retries, and platform handling
- [`PORTABILITY.md`](docs/PORTABILITY.md): Bash dependency policy and Linux/macOS portability notes
- [`MEMORY-ACQUISITION.md`](docs/MEMORY-ACQUISITION.md): `/proc`, core dumps, targeted live memory, and operational risk
- [`FORENSIC-CONSIDERATIONS.md`](docs/FORENSIC-CONSIDERATIONS.md): preservation, integrity, security, limitations, and production impact

## Requirements and compatibility

Bash requires a Unix-like forensic workstation with OpenSSH and a SHA-256 utility (`sha256sum`, `shasum`, or `openssl`); Python is not required. PowerShell requires Windows PowerShell or PowerShell 7 with Windows OpenSSH.

Junosleuth is intended for Junos OS and Junos OS Evolved. Actual command, filesystem, shell, `/proc`, and JMRT availability depends on platform, Routing Engine, software release, and account permissions.

See [`SSH-AND-PLATFORM.md`](docs/SSH-AND-PLATFORM.md) for Junos login-class and feature-specific permission guidance.

Project site: https://jreisdorffer.github.io/junosleuth/

## Repository

https://github.com/jreisdorffer/junosleuth

## License

Junosleuth is distributed under the **Beer-Ware License (Revision 42, adapted for Junosleuth)**. See [`LICENSE`](LICENSE).

The beer is optional; retaining the license notice is not.

## Trademark and affiliation notice

Junosleuth is an **independent, open-source project** and is not affiliated with, endorsed by, sponsored by, or otherwise associated with Juniper Networks, Inc.

**Juniper Networks**, **Juniper**, **Junos**, and related names and marks are trademarks and/or registered trademarks of Juniper Networks, Inc. and/or its affiliates. They are used only to identify compatibility and intended platforms.

## Disclaimer

Use Junosleuth only on systems you are authorized to investigate. Evidence can contain sensitive network, configuration, authentication, and infrastructure information and should be stored on protected forensic storage.

Any live response changes some system state. Test collection procedures, especially live-memory acquisition, on representative equipment before production use.

**Junosleuth: Collect first. Analyze offline. Remediate deliberately.**
