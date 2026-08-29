# SSH and Platform Handling

## Landing modes

Junosleuth supports both common SSH scenarios:

- **Direct Junos CLI:** operational commands are sent directly.
- **Underlying OS shell:** Junos operational commands are executed through `cli -c`.

The selected mode is recorded in `meta/manifest.txt` as `remote_mode=cli` or `remote_mode=shell`.

For OS collection from a direct CLI account, `start shell command ...` is used where permissions permit.

## Login notices

Some devices print a login notice on every SSH connection. Junosleuth learns the exact common startup prefix and stores it under `meta/`.

Original SSH stdout is retained under `raw/cli/` and `raw/shell/`. Analyst-facing copies remove only the learned prefix.

## Transport versus command status

Junos can return SSH status `0` while printing a CLI command error. Junosleuth therefore records both transport and semantic status.

```text
# exit_status=0
# semantic_status=command_error
```

SSH exit status `255` is treated as a transport failure and retried according to collector policy.

## Platform detection

Fingerprinting uses evidence including:

```text
show version detail
show chassis hardware detail
```

Traditional Junos can expose FreeBSD utilities such as `netstat`, `sockstat`, and `stat -f`. Junos OS Evolved can expose Linux equivalents such as `ss`, `ip`, and `stat -c`.

If platform detection is inconclusive, Junosleuth uses a conservative profile.

## Permissions

CLI access does not imply unrestricted shell or filesystem access. A failed collection attempt should not be interpreted as proof that an artifact or capability is absent.

Junos authorization is controlled by the login class assigned to the SSH user. Permission flags define broad access, and `allow-commands` or `deny-commands` regular expressions can further allow or block individual operational commands. Validate the effective permissions for the account before using it for an incident-response run.

The command below can help confirm what the current account is allowed to do:

```text
show cli authorization
```

## Feature permission guide

| Junosleuth feature | Typical Junos access needed |
|---|---|
| Baseline CLI collection | SSH access to Junos operational mode and permission to run the collected `show`, `file list`, and related operational commands. A restricted login class can work if it explicitly allows the required commands. |
| Configuration capture | Permission to view configuration output, such as `show configuration | display set`. On restricted accounts, configuration visibility may omit sensitive data or be blocked entirely. |
| Log and file listings | Permission to run Junos log and file-listing commands such as `show log ...` and `file list ... detail`. Visibility can vary by login class and platform. |
| JMRT collection | `admin` privilege for `request system malware-scan ...` commands. Junosleuth uses `clean-action warn` for the quick scan. |
| OS-shell collection | `shell` or `maintenance` privilege when the account lands in the Junos CLI and Junosleuth must use `start shell command ...`. If the account already lands in an OS shell, the account still needs OS permissions to run the shell commands. |
| File acquisition | OS-shell command access for `find`, `stat`, and hashing commands, plus SCP/SFTP read access to the selected remote files. File reads still depend on Unix ownership and mode bits on the Routing Engine. |
| Existing core acquisition | File acquisition permissions plus read access to core and crash paths such as `/var/core`, `/var/crash`, and matching files under `/var/tmp`. |
| Targeted live-memory acquisition | OS-shell access and permission to read `/proc/<pid>/maps` or `/proc/<pid>/map` and `/proc/<pid>/mem` for the requested PIDs. In practice this may require a highly privileged account for many system processes. |

## Recommended permission statement

For a temporary incident-response login class intended to support all Junosleuth features, start with:

```text
set system login class junosleuth-ir permissions [ admin shell view view-configuration ]
```

This gives the account:

| Permission | Why Junosleuth may need it |
|---|---|
| `view` | baseline operational `show` commands, file listings, logs, and `show cli authorization` |
| `view-configuration` | `show configuration | display set` evidence |
| `admin` | `request system malware-scan ...` for JMRT collection |
| `shell` | `start shell command ...` for OS-shell, file, core, `/proc`, and memory-related collection |

This permission set authorizes the required Junos CLI and shell entry points, but it does not override Unix file ownership or mode bits on the Routing Engine. File acquisition and live-memory acquisition can still fail for protected paths or protected PIDs.

If the incident procedure explicitly requires access to protected Routing Engine files or process memory, use a short-lived, tightly controlled privileged account for that collection window. One broad emergency class is:

```text
set system login class junosleuth-ir-privileged permissions [ admin maintenance shell view view-configuration ]
```

`maintenance` can allow deeper system maintenance access, including shell-related maintenance operations. It also grants potentially disruptive capabilities outside Junosleuth's intended collection behavior, so use it only with explicit approval and remove it after collection.

## Suggested access model

For normal evidence collection, prefer a named incident-response account or temporary login class that grants only the required operational commands. Avoid using broad `all` permissions unless your incident procedure requires it and the operational risk has been accepted.

For deeper collection features, add access only for the required phase:

| Phase | Suggested access |
|---|---|
| Basic state capture | operational command access for baseline `show`, log, configuration, and file-listing commands |
| JMRT evidence | add `admin` access for `request system malware-scan` |
| Shell, file, and `/proc` evidence | add `shell` or `maintenance` access, plus filesystem read permissions for the target paths |
| Live memory evidence | use a highly controlled privileged account only for the explicit memory-acquisition window |

Remove temporary access after collection when your change-control and evidence-preservation process allows it.
