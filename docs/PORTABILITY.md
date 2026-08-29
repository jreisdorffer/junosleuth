# Bash Portability and Dependencies

The Bash collector is intended to remain usable from ordinary Linux, macOS, and Unix-like forensic workstations without requiring a scripting-language runtime such as Python, Perl, or Ruby.

## Dependency policy

`junosleuth.sh` should not introduce a runtime dependency beyond Bash, OpenSSH, and commonly available Unix command-line utilities unless a dependency is explicitly optional and documented.

The current collector does **not** require Python.

## Workstation requirements

### Required for normal collection

- Bash
- OpenSSH `ssh`
- common Unix utilities such as `awk`, `sed`, `grep`, `find`, `sort`, `head`, `tail`, `wc`, `tr`, `dd`, `cmp`, `cp`, `mv`, `rm`, and `date`
- one SHA-256 implementation:
  - `sha256sum`, or
  - `shasum`, or
  - `openssl`

### Required only for file acquisition

- OpenSSH `scp`

### Not required

Junosleuth does not require:

```text
python / python3
perl
ruby
jq
bc
pv
rsync
curl
wget
```

The collector performs a startup check for `ssh` and a usable SHA-256 implementation. It checks for `scp` only when `--acquire-files` is enabled.

## Target-side commands

Junosleuth uses commands already present on the target platform where available. These vary between traditional Junos and Junos OS Evolved.

Examples include:

```text
cli
ps
find
stat
netstat / sockstat
ss / ip
dd
sha256 / sha256sum / openssl
```

Target-side command absence is generally handled as an unsupported/best-effort collection result rather than as a workstation dependency.

## Login-banner handling

Repeated SSH login notices are learned as complete common lines from two harmless probes. The collector uses standard `awk`, `head`, `tail`, and `cmp` operations to remove only an exact learned prefix from analyst-facing text output while preserving raw SSH output separately.

No interpreter is required for banner handling.

For binary live-memory chunks, the exact learned banner bytes are checked before removal. The raw temporary chunk exists only on the forensic workstation; memory data is never staged on router storage.

## Memory acquisition

Targeted live-memory acquisition performs hexadecimal address handling with Bash integer arithmetic and deliberately rejects address ranges that cannot be represented safely as positive signed 64-bit values.

This is a conservative portability choice. It is preferable to skipping an unusual mapping and recording that fact rather than silently depending on interpreter-specific arbitrary-precision arithmetic.

Readable mappings are acquired in bounded chunks. Transfer throttling is dependency-free: Junosleuth transfers one chunk at a time and inserts a calculated sleep interval between chunks. This is intentionally coarser than a `pv`-style byte-accurate limiter but avoids adding another runtime dependency.

## GNU/BSD compatibility

The collector avoids GNU-only `sort -z` / `xargs -0` for the final evidence manifest. It creates a deterministic newline-delimited file list using portable `find` and `sort`, then hashes each Junosleuth-generated evidence filename individually.

Junosleuth itself generates evidence filenames without newline characters. Files acquired from the router are mapped to controlled local paths rather than trusted as arbitrary local filenames.

## Portability testing

Before releases, the Bash collector should at minimum be checked with:

```bash
bash -n junosleuth.sh
grep -nE '\b(python3?|perl|ruby|jq|bc|pv|rsync|curl|wget)\b' junosleuth.sh
```

Recommended runtime testing includes current Linux and macOS hosts plus representative traditional Junos and Junos OS Evolved targets.
