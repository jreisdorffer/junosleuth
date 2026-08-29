# Forensic and Operational Considerations

## Evidence preservation

Junosleuth is evidence-focused, not non-invasive. Any live interaction can create authentication records, command-accounting entries, process activity, filesystem access-time changes, and network traffic.

Whenever possible, collect volatile evidence before rebooting, upgrading, restarting services, cleaning malware, or changing configuration.

## Actions intentionally avoided

Initial collection does not intentionally:

- reboot or upgrade the router;
- restart or terminate processes;
- delete suspicious files;
- change Junos configuration;
- clean detected malware;
- install software or test packages;
- suspend processes for memory acquisition.

Remediation should be a separate phase.

## Routing Engine impact

Ordinary CLI and metadata collection is designed to be comparatively low impact, but no command can be guaranteed non-impacting on every Junos platform.

File/core acquisition adds disk and SSH I/O. Targeted live-memory acquisition adds more sustained Routing Engine and memory-bus activity and should be treated as an explicit production-risk decision.

For high-severity incidents on critical infrastructure, consider migrating traffic to known-good infrastructure and preserving the affected Routing Engine/storage for deeper offline analysis where operationally possible.

## Evidence integrity

The completed package contains `SHA256SUMS.txt`.

File acquisition also attempts remote/local SHA-256 comparison so the responder can verify that the local artifact matches the content read from the router.

For formal investigations, maintain separate chain-of-custody records such as case ID, device/serial, operator, collection start/end UTC, evidence location, package hash, and transfer history.

## Evidence security

Collections can contain sensitive information including topology, IP addressing, usernames, configuration, authentication data, VPN/SNMP information, routing relationships, process memory, and internal infrastructure details.

Store evidence on encrypted, access-controlled forensic storage and handle memory artifacts as especially sensitive.

## Important limitations

Junosleuth is not:

- an EDR;
- a malware-removal product;
- proof that a router is clean;
- a replacement for Juniper support/JTAC;
- a physical disk-imaging solution;
- an atomic physical-memory acquisition framework.

A negative JMRT result or absence of a known artifact must not be interpreted as proof that compromise did not occur.

Filesystem, shell, `/proc`, and command availability vary across Junos OS, Junos OS Evolved, hardware, Routing Engines, releases, and account privileges.

## Authorization

Use Junosleuth only against infrastructure for which you are authorized to perform incident-response or forensic collection.
