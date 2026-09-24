# Memory Acquisition

Junosleuth has three memory-related collection levels.

## `/proc` metadata and memory maps

With shell collection enabled, Junosleuth performs best-effort collection of available process metadata such as:

```text
/proc/<pid>/status
/proc/<pid>/cmdline
/proc/<pid>/maps
/proc/<pid>/map
/proc/<pid>/exe
/proc/<pid>/file
/proc/<pid>/cwd
```

This is useful for process identity, executable provenance, mapped files, and address-space context. Availability depends on platform, release, and permissions.

## Existing core dumps

With file acquisition enabled, Junosleuth discovers existing core/crash evidence in common locations including `/var/core/` and `/var/crash/`, plus core-specific candidates in `/var/tmp`.

Junosleuth does not intentionally crash a process to create these files.

## Experimental targeted live memory

Live memory is disabled by default and requires explicit numeric PIDs:

```text
--acquire-memory 1234,5678
-AcquireMemory "1234,5678"
```

Where `/proc/<pid>/mem` is readable, Junosleuth records process identity and memory maps, reads readable mapped regions sequentially, streams them directly to the forensic workstation, records expected/actual byte counts, hashes acquired regions locally, and captures the map again afterward.

It does **not** automatically dump every process, suspend or signal the process, intentionally crash it, or stage a memory dump on router storage.

The Bash implementation does **not** require Python or another scripting-language runtime. Region parsing, address conversion, chunking, banner handling, and conservative rate limiting use Bash and standard Unix utilities.

## Operational safeguards

- explicit PID selection
- sequential acquisition only
- bounded region chunks
- default workstation receive limit of 5 MiB/s
- no router-side staging
- Routing Engine/process/storage/memory health evidence before and after

The rate can be adjusted with `--memory-rate-mbps` or `-MemoryRateMBps`.

## Operational risk

Live-memory acquisition is more intrusive than ordinary CLI/file collection. It can increase Routing Engine CPU, memory-bus activity, SSH throughput, and control-plane scheduling pressure.

Forwarding may occur separately on Packet Forwarding Engines, but Routing Engine pressure can still affect routing protocols, convergence, management services, and availability.

Use targeted memory only when justified and test it on representative hardware/releases before routine production use.

## Consistency limitation

The process continues running during acquisition. The result is therefore a rolling view rather than an atomic snapshot.

Junosleuth captures memory maps before and after acquisition so later analysis can identify mapping changes. It deliberately does not freeze critical Junos processes merely to improve snapshot consistency.
