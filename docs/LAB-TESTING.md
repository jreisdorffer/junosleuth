# Lab Testing

This guide describes the optional vJunos lab helpers under `tests/`. They are intended for authorized defensive testing only.

The lab helpers cover three jobs:

| Script | Purpose |
|---|---|
| `tests/vjunos-lab-deploy.sh` | deploy, configure, inspect, reset, and revert a disposable vJunos-router VM on a remote KVM/libvirt host |
| `tests/simulate-unc3886-indicators.sh` | create benign indicator artifacts for collection and detection validation |
| `tests/validate-vjunos-features.sh` | run systematic Junosleuth feature checks and write a Markdown report |

## Remote vJunos lab

Copy the example environment and edit paths for your lab host:

```bash
cp tests/vjunos-lab.env.example tests/vjunos-lab.env
```

Install KVM/libvirt prerequisites on a Debian or Ubuntu remote host:

```bash
tests/vjunos-lab-deploy.sh --env tests/vjunos-lab.env install-prereqs
```

Deploy and configure the VM:

```bash
tests/vjunos-lab-deploy.sh --env tests/vjunos-lab.env deploy
```

The default security model keeps the router management interface on the remote host's private libvirt NAT network. The script does not create a public port forward. It generates a temporary root SSH key and a random root password on the remote lab host.

Check status:

```bash
tests/vjunos-lab-deploy.sh --env tests/vjunos-lab.env status
```

Reset to a clean lab overlay:

```bash
tests/vjunos-lab-deploy.sh --env tests/vjunos-lab.env reset
```

Revert lab resources:

```bash
tests/vjunos-lab-deploy.sh --env tests/vjunos-lab.env revert
```

`revert` removes the VM, qcow2 overlay, isolated lab networks, and generated router credentials. It preserves the uploaded base image unless `--remove-base-image` is supplied.

## Benign indicator simulation

The indicator simulator creates harmless test artifacts under `/var/tmp/.junosleuth-lab/unc3886` and `/tmp`. It also starts a sleeping worker process so process and memory collection can be validated. When `--memory-analysis` is used, the worker carries a benign marker string in process memory and the test report searches the acquired memory regions for that marker.

Install indicators:

```bash
tests/simulate-unc3886-indicators.sh install -H 192.168.122.151 -u root
```

Run collection and detection checks:

```bash
tests/simulate-unc3886-indicators.sh test -H 192.168.122.151 -u root --memory --cleanup-after
```

Run collection plus memory-marker analysis:

```bash
tests/simulate-unc3886-indicators.sh test -H 192.168.122.151 -u root --memory-analysis --cleanup-after
```

Remove indicators:

```bash
tests/simulate-unc3886-indicators.sh cleanup -H 192.168.122.151 -u root
```

The simulator does not deploy malware, modify system binaries, exploit the router, or install persistence. It uses text markers, hidden files, log messages, timestamps, and a temporary sleeping process.

## Systematic feature validation

Run the full validator against a lab router:

```bash
tests/validate-vjunos-features.sh -H 192.168.122.151 -u root -o ./junosleuth-validation
```

The validator runs these cases:

| Case | Coverage |
|---|---|
| `baseline` | default Junos CLI evidence and final hashing |
| `shell` | OS-shell evidence, process state, socket state, `/proc` metadata |
| `file-acquisition` | metadata, candidate discovery, file copy, local hash records |
| `jmrt` | warn-only JMRT quick scan and integrity check |
| `memory` | targeted live-memory acquisition from a temporary sleeping process |

Each run writes `summary.md` under a timestamped validation directory. The report links each collector log and evidence directory.
