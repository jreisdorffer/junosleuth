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
