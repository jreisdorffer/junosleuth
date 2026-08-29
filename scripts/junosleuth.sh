#!/usr/bin/env bash
# ==============================================================================
# JUNOSLEUTH - Incident Response & Forensic Acquisition for Junos
# Bash Collector
# ==============================================================================
# Project:    Junosleuth
# Repository: https://github.com/jreisdorffer/junosleuth
# License:    Beer-Ware License (Revision 42, adapted); see LICENSE
#
# Junosleuth is an independent open-source project and is not affiliated with,
# endorsed by, sponsored by, or otherwise associated with Juniper Networks,
# Inc. "Juniper Networks", "Juniper", "Junos", and related names and marks are
# trademarks and/or registered trademarks of Juniper Networks, Inc. and/or its
# affiliates. All such trademarks remain the property of their respective owners.
#
# Intended only for authorized incident response, forensic investigation,
# laboratory testing, and defensive security research.
#
# The collector preserves unmodified SSH stdout under raw/ and writes cleaned,
# analyst-facing output under cli/ and shell/. A repeated SSH/Junos login notice
# is learned during startup, stored once in meta/login_notice.txt, and removed
# only from the cleaned copies.
# ==============================================================================

set -u
set -o pipefail

HOST=""
USER_NAME=""
OUT_BASE="./junosleuth-evidence"
PORT=22
RUN_JMRT=0
RUN_SHELL=0
ACQUIRE_FILES=0
ACQUIRE_MEMORY=""
MEMORY_RATE_MBPS=5
MEMORY_CHUNK_MB=64
REMOTE_MODE="unknown"
PLATFORM_FAMILY="unknown"
SSH_RETRIES=3
SSH_RETRY_DELAY=1

usage() {
  cat <<'EOF'
Usage: junosleuth.sh -H HOST -u USER [options]

Required:
  -H, --host HOST          Juniper management IP/FQDN
  -u, --user USER          SSH username

Options:
  -p, --port PORT          SSH port (default: 22)
  -o, --output DIR         Evidence directory (default: ./junosleuth-evidence)
      --jmrt               Run JMRT in WARN-ONLY mode
      --shell              Collect additional OS-level metadata
      --acquire-files      Acquire selected forensic files and existing core dumps
      --acquire-memory PIDS
                           EXPERIMENTAL: acquire readable memory mappings for
                           comma-separated target PIDs (implies --shell)
      --memory-rate-mbps N Advisory local receive-rate limit (default: 5 MB/s)
  -h, --help               Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--host) HOST="${2:-}"; shift 2 ;;
    -u|--user) USER_NAME="${2:-}"; shift 2 ;;
    -p|--port) PORT="${2:-}"; shift 2 ;;
    -o|--output) OUT_BASE="${2:-}"; shift 2 ;;
    --jmrt) RUN_JMRT=1; shift ;;
    --shell) RUN_SHELL=1; shift ;;
    --acquire-files) ACQUIRE_FILES=1; shift ;;
    --acquire-memory) ACQUIRE_MEMORY="${2:-}"; RUN_SHELL=1; shift 2 ;;
    --memory-rate-mbps) MEMORY_RATE_MBPS="${2:-5}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$HOST" && -n "$USER_NAME" ]] || { usage; exit 2; }
[[ "$MEMORY_RATE_MBPS" =~ ^[0-9]+$ ]] && (( MEMORY_RATE_MBPS >= 1 )) || { echo "ERROR: --memory-rate-mbps must be >= 1" >&2; exit 2; }
if [[ -n "$ACQUIRE_MEMORY" ]] && ! [[ "$ACQUIRE_MEMORY" =~ ^[0-9]+(,[0-9]+)*$ ]]; then echo "ERROR: --acquire-memory expects comma-separated numeric PIDs" >&2; exit 2; fi
command -v ssh >/dev/null 2>&1 || { echo "ERROR: ssh not found" >&2; exit 1; }
if [[ "$ACQUIRE_FILES" -eq 1 ]]; then
  command -v scp >/dev/null 2>&1 || { echo "ERROR: scp not found (required by --acquire-files)" >&2; exit 1; }
fi
if command -v sha256sum >/dev/null 2>&1; then
  HOST_SHA256_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HOST_SHA256_TOOL="shasum"
elif command -v openssl >/dev/null 2>&1; then
  HOST_SHA256_TOOL="openssl"
else
  echo "ERROR: need sha256sum, shasum, or openssl for evidence hashing" >&2
  exit 1
fi

host_sha256() {
  local f="$1"
  case "$HOST_SHA256_TOOL" in
    sha256sum) sha256sum "$f" | awk '{print $1}' ;;
    shasum) shasum -a 256 "$f" | awk '{print $1}' ;;
    openssl) openssl dgst -sha256 "$f" | awk '{print $NF}' ;;
  esac
}

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_HOST="$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_')"
OUT="${OUT_BASE%/}/${SAFE_HOST}_${TS}"
mkdir -p "$OUT"/{cli,shell,raw/cli,raw/shell,files,memory,meta}
chmod 700 "$OUT"

SSH_OPTS=(
  -T
  -p "$PORT"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=ask
)
SSH=(ssh "${SSH_OPTS[@]}" "${USER_NAME}@${HOST}")

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$OUT/meta/collector.log"
}

slug() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' |
    sed -E 's/[^a-z0-9]+/_/g;s/^_+//;s/_+$//' | cut -c1-100
}

# Execute one SSH command. Exit 255 is retried because it means SSH transport
# failure, not a Junos operational command failure.
ssh_raw() {
  local remote="$1" stdout_file="$2" stderr_file="$3" attempts_file="$4"
  local attempt rc=255
  for ((attempt=1; attempt<=SSH_RETRIES; attempt++)); do
    : > "$stdout_file"; : > "$stderr_file"
    "${SSH[@]}" "$remote" >"$stdout_file" 2>"$stderr_file"
    rc=$?
    if [[ "$rc" -ne 255 || "$attempt" -eq "$SSH_RETRIES" ]]; then
      printf '%s' "$attempt" > "$attempts_file"
      return "$rc"
    fi
    sleep $((SSH_RETRY_DELAY * attempt))
  done
}

remote_cli_cmd() {
  local cmd="$1"
  if [[ "$REMOTE_MODE" == "cli" ]]; then
    printf '%s' "$cmd"
  else
    printf 'cli -c %q' "$cmd"
  fi
}

remote_shell_cmd() {
  local cmd="$1"
  if [[ "$REMOTE_MODE" == "cli" ]]; then
    cmd="${cmd//\"/\\\"}"
    printf 'start shell command "%s"' "$cmd"
  else
    printf '%s' "$cmd"
  fi
}

semantic_status() {
  local rc="$1" file="$2"
  if [[ "$rc" -eq 255 ]]; then printf 'transport_error'; return; fi
  if [[ "$rc" -ne 0 ]]; then printf 'remote_error'; return; fi
  if grep -Eqi '^[[:space:]]*(error:|syntax error|unknown command:|invalid command|permission denied|command not found)' "$file"; then
    printf 'command_error'; return
  fi
  printf 'ok'
}

# Remove only the exact learned common login-notice prefix.
# Raw output is always kept separately and never modified.
strip_login_notice() {
  local raw="$1" clean="$2" notice="$OUT/meta/login_notice.txt"
  local notice_lines prefix
  if [[ ! -s "$notice" ]]; then
    cp "$raw" "$clean"
    return
  fi

  # Login notices are learned as complete repeated lines.  Compare those exact
  # lines before removing them; otherwise preserve the raw content unchanged.
  notice_lines="$(wc -l < "$notice" | tr -d ' ')"
  [[ "$notice_lines" =~ ^[0-9]+$ ]] || notice_lines=0
  if (( notice_lines > 0 )); then
    prefix="$OUT/meta/.notice_prefix.$$"
    head -n "$notice_lines" "$raw" > "$prefix" 2>/dev/null || true
    if cmp -s "$notice" "$prefix"; then
      tail -n "+$((notice_lines + 1))" "$raw" > "$clean"
    else
      cp "$raw" "$clean"
    fi
    rm -f "$prefix"
  else
    cp "$raw" "$clean"
  fi
}

# Determine whether ssh user@router "show ..." lands directly in Junos CLI or
# whether commands must be wrapped in cli -c from an OS shell.
detect_remote_mode() {
  local out err att rc
  out="$OUT/meta/probe_direct.raw"; err="$OUT/meta/probe_direct.stderr"; att="$OUT/meta/.att"
  ssh_raw "show system uptime" "$out" "$err" "$att"; rc=$?
  if [[ "$rc" -eq 0 ]] && ! grep -Eqi 'unknown command|command not found|syntax error' "$out"; then
    if grep -Eqi 'Current time|System booted|Protocols started|uptime' "$out"; then
      REMOTE_MODE="cli"; rm -f "$att"; return 0
    fi
  fi

  out="$OUT/meta/probe_shell.raw"; err="$OUT/meta/probe_shell.stderr"
  ssh_raw "cli -c 'show system uptime'" "$out" "$err" "$att"; rc=$?
  if [[ "$rc" -eq 0 ]] && ! grep -Eqi 'unknown command|command not found|syntax error' "$out"; then
    if grep -Eqi 'Current time|System booted|Protocols started|uptime' "$out"; then
      REMOTE_MODE="shell"; rm -f "$att"; return 0
    fi
  fi
  rm -f "$att"
  return 1
}

# Learn a repeated login notice by comparing the common leading bytes/lines of
# two harmless Junos CLI commands. This avoids hard-coding a customer's banner.
learn_login_notice() {
  local a="$OUT/meta/banner_probe_a.raw"
  local b="$OUT/meta/banner_probe_b.raw"
  local ea="$OUT/meta/banner_probe_a.stderr"
  local eb="$OUT/meta/banner_probe_b.stderr"
  local aa="$OUT/meta/.a" ab="$OUT/meta/.b"
  local ca cb tmp

  ca="$(remote_cli_cmd "show system uptime")"
  cb="$(remote_cli_cmd "show version")"
  ssh_raw "$ca" "$a" "$ea" "$aa" || true
  ssh_raw "$cb" "$b" "$eb" "$ab" || true
  rm -f "$aa" "$ab"

  # Learn only complete lines that are identical at the beginning of both
  # probes.  awk is sufficient here and avoids requiring an interpreter.
  tmp="$OUT/meta/.login_notice.$$"
  awk 'NR==FNR { first[NR]=$0; n=NR; next }
       { if (!stop && FNR<=n && $0==first[FNR]) { print first[FNR] } else { stop=1 } }' \
      "$a" "$b" > "$tmp"
  mv "$tmp" "$OUT/meta/login_notice.txt"

  if [[ -s "$OUT/meta/login_notice.txt" ]]; then
    log "Learned repeated login notice; preserved in meta/login_notice.txt"
  else
    log "No stable repeated login notice detected"
  fi
}

run_cli() {
  local cmd="$1" name="${2:-$(slug "$1")}"
  local raw="$OUT/raw/cli/${name}.raw.txt"
  local file="$OUT/cli/${name}.txt"
  local err="$OUT/meta/.err.$$" att="$OUT/meta/.att.$$"
  local remote rc semantic attempts

  log "CLI: $cmd"
  remote="$(remote_cli_cmd "$cmd")"
  ssh_raw "$remote" "$raw" "$err" "$att"; rc=$?
  strip_login_notice "$raw" "$file"

  if [[ -s "$err" ]]; then
    { echo; echo "### $(date -u +%FT%TZ) | $cmd"; cat "$err"; } >> "$OUT/meta/ssh_stderr.log"
  fi

  semantic="$(semantic_status "$rc" "$file")"
  attempts="$(cat "$att" 2>/dev/null || echo 0)"
  {
    printf '\n# collected_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '# command=%s\n' "$cmd"
    printf '# remote_mode=%s\n' "$REMOTE_MODE"
    printf '# raw_output=%s\n' "raw/cli/${name}.raw.txt"
    printf '# exit_status=%s\n' "$rc"
    printf '# semantic_status=%s\n' "$semantic"
    printf '# ssh_attempts=%s\n' "$attempts"
  } >> "$file"

  rm -f "$err" "$att"
  sleep 0.25
}

run_shell() {
  local cmd="$1" name="${2:-$(slug "$1")}"
  local raw="$OUT/raw/shell/${name}.raw.txt"
  local file="$OUT/shell/${name}.txt"
  local err="$OUT/meta/.err.$$" att="$OUT/meta/.att.$$"
  local remote rc semantic attempts

  log "SHELL: $cmd"
  remote="$(remote_shell_cmd "$cmd")"
  ssh_raw "$remote" "$raw" "$err" "$att"; rc=$?
  strip_login_notice "$raw" "$file"

  if [[ -s "$err" ]]; then
    { echo; echo "### $(date -u +%FT%TZ) | SHELL: $cmd"; cat "$err"; } >> "$OUT/meta/ssh_stderr.log"
  fi

  semantic="$(semantic_status "$rc" "$file")"
  attempts="$(cat "$att" 2>/dev/null || echo 0)"
  {
    printf '\n# collected_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '# shell_command=%s\n' "$cmd"
    printf '# remote_mode=%s\n' "$REMOTE_MODE"
    printf '# raw_output=%s\n' "raw/shell/${name}.raw.txt"
    printf '# exit_status=%s\n' "$rc"
    printf '# semantic_status=%s\n' "$semantic"
    printf '# ssh_attempts=%s\n' "$attempts"
  } >> "$file"

  rm -f "$err" "$att"
  sleep 0.25
}

detect_platform() {
  run_cli "show version detail" "00_platform_version"
  local text="$OUT/cli/00_platform_version.txt"
  if grep -Eqi 'Junos OS Evolved|JUNOS-EVO' "$text"; then
    PLATFORM_FAMILY="evolved"
  elif grep -Eqi 'Junos|JUNOS' "$text"; then
    PLATFORM_FAMILY="traditional"
  else
    PLATFORM_FAMILY="unknown"
  fi
  echo "platform_family=$PLATFORM_FAMILY" >> "$OUT/meta/manifest.txt"
}

log "Starting Junosleuth collection"

cat > "$OUT/meta/manifest.txt" <<EOF
project=Junosleuth
repository=https://github.com/jreisdorffer/junosleuth
collector_host=$(hostname 2>/dev/null || true)
collector_user=$(id -un 2>/dev/null || true)
target=$HOST
ssh_user=$USER_NAME
ssh_port=$PORT
utc_started=$(date -u +%FT%TZ)
jmrt_enabled=$RUN_JMRT
shell_enabled=$RUN_SHELL
file_acquisition_enabled=$ACQUIRE_FILES
memory_acquisition_pids=$ACQUIRE_MEMORY
memory_rate_mbps=$MEMORY_RATE_MBPS
memory_acquisition_experimental=$([[ -n "$ACQUIRE_MEMORY" ]] && echo 1 || echo 0)
recommended_file_paths=/var/log,/var/tmp,/tmp,/var/crash,/var/core,/var/core/re,/var/core/re0,/var/core/re1,/config,/root,/home,/mfs/var/etc,/var/db/config,/var/rundb+
recommended_priority_files=/var/log/messages,/var/log/interactive-commands,/var/log/authorization,/mfs/var/etc/syslog.conf,/mfs/var/etc/syslog.conf0,/var/rundb+,/config/usage_db,/var/db/config/usage_db,/usr/lib/libjucomm.so.1
EOF

if ! detect_remote_mode; then
  log "ERROR: Could not determine SSH login mode"
  exit 1
fi
echo "remote_mode=$REMOTE_MODE" >> "$OUT/meta/manifest.txt"
log "Detected SSH login mode: $REMOTE_MODE"

learn_login_notice
detect_platform

# Platform / identity
run_cli "show chassis hardware detail" "01_show_chassis_hardware_detail"
run_cli "show system uptime" "02_show_system_uptime"
run_cli "show system users" "03_show_system_users"
run_cli "show system alarms" "04_show_system_alarms"
run_cli "show chassis alarms" "05_show_chassis_alarms"
run_cli "show system storage" "06_show_system_storage"
run_cli "show system core-dumps" "07_show_system_core_dumps"
run_cli "show chassis routing-engine" "08_show_chassis_routing_engine"
run_cli "show system memory" "09_show_system_memory"

# Volatile state
run_cli "show system processes extensive" "10_show_system_processes_extensive"
run_cli "show system connections" "11_show_system_connections"
if [[ "$PLATFORM_FAMILY" == "traditional" ]]; then
  run_cli "show system connections extensive" "12_show_system_connections_extensive"
fi
run_cli "show system statistics" "13_show_system_statistics"
run_cli "show task memory" "14_show_task_memory"

# Network
run_cli "show interfaces terse" "20_show_interfaces_terse"
run_cli "show interfaces extensive" "21_show_interfaces_extensive"
run_cli "show route summary" "22_show_route_summary"
run_cli "show route forwarding-table summary" "23_show_forwarding_table_summary"
run_cli "show arp no-resolve" "24_show_arp_no_resolve"
run_cli "show bgp summary" "25_show_bgp_summary"

# Config / logs
run_cli "show system commit" "30_show_system_commit"
run_cli "show configuration | display set | no-more" "31_configuration_display_set"
run_cli "show log messages | no-more" "40_log_messages"
run_cli "show log interactive-commands | no-more" "41_log_interactive_commands"
run_cli "show log authorization | no-more" "42_log_authorization"
run_cli "file list /var/log detail" "43_file_list_var_log"
run_cli "file list /var/tmp detail" "44_file_list_var_tmp"
run_cli "file list /tmp detail" "45_file_list_tmp"

if [[ "$RUN_JMRT" -eq 1 ]]; then
  run_cli "request system malware-scan quick-scan clean-action warn" "50_jmrt_quick_scan_warn"
  run_cli "request system malware-scan integrity-check" "51_jmrt_integrity_check"
fi

if [[ "$RUN_SHELL" -eq 1 ]]; then
  run_shell "uname -a" "60_uname"
  run_shell "date -u" "61_date_utc"
  run_shell "uptime" "62_uptime"
  run_shell "ps auxww" "63_ps_auxww"
  if [[ "$PLATFORM_FAMILY" == "evolved" ]]; then
    run_shell "ss -anp" "64_ss_anp"
    run_shell "ip addr show" "65_ip_addr"
  else
    run_shell "netstat -an" "64_netstat_an"
    run_shell "sockstat -4 -6" "65_sockstat"
  fi
  run_shell "mount" "66_mount"
  run_shell "df -h" "67_df_h"
  run_shell "ls -laT /var/tmp /tmp /var/log 2>&1" "68_writable_dirs_listing"
  run_shell "find /var/tmp /tmp -type f -ls 2>&1" "69_writable_files_find"
  run_shell "who -a 2>&1 || w 2>&1" "70_logged_in_users"
  run_shell "ps -ax -o pid,ppid,uid,lstart,args 2>&1 || ps auxww 2>&1" "71_process_provenance"
  run_shell "find /proc -maxdepth 2 \\( -name status -o -name cmdline -o -name maps -o -name map \\) -type f -print 2>/dev/null" "72_proc_metadata_index"
  run_shell "for p in /proc/[0-9]*; do [ -d \"$p\" ] || continue; echo \"===== $p =====\"; for x in status cmdline maps map; do [ -r \"$p/$x\" ] && { echo \"--- $x ---\"; cat \"$p/$x\"; echo; }; done; for x in exe file cwd; do [ -e \"$p/$x\" ] && { echo \"--- $x ---\"; ls -ld \"$p/$x\" 2>&1; }; done; done 2>&1" "73_proc_metadata"
fi

# Optional file acquisition. SCP may require shell/SFTP capability on the account.
if [[ "$ACQUIRE_FILES" -eq 1 ]]; then
  log "File acquisition enabled"
  : > "$OUT/meta/acquired_files_manifest.txt"

  remote_size() {
    local f="$1" cmd tmp="$OUT/meta/.size.$$" err="$OUT/meta/.sizeerr.$$" att="$OUT/meta/.sizeatt.$$" rc s=""
    if [[ "$PLATFORM_FAMILY" == "evolved" ]]; then cmd="stat -c %s $(printf '%q' "$f")"; else cmd="stat -f %z $(printf '%q' "$f")"; fi
    ssh_raw "$(remote_shell_cmd "$cmd")" "$tmp" "$err" "$att"; rc=$?
    [[ "$rc" -eq 0 ]] && s="$(tr -d '\r\n' < "$tmp")"
    rm -f "$tmp" "$err" "$att"
    printf '%s' "$s"
  }

  remote_hash() {
    local f="$1" cmd tmp="$OUT/meta/.hash.$$" err="$OUT/meta/.hasherr.$$" att="$OUT/meta/.hashatt.$$" rc h=""
    for cmd in "sha256 -q $(printf '%q' "$f")" "sha256sum $(printf '%q' "$f")" "openssl dgst -sha256 $(printf '%q' "$f")"; do
      ssh_raw "$(remote_shell_cmd "$cmd")" "$tmp" "$err" "$att"; rc=$?
      if [[ "$rc" -eq 0 && -s "$tmp" ]]; then
        h="$(awk '{print $NF}' "$tmp" | tr -d '\r\n')"
        [[ "$cmd" == sha256sum* ]] && h="$(awk '{print $1}' "$tmp" | tr -d '\r\n')"
        break
      fi
    done
    rm -f "$tmp" "$err" "$att"
    printf '%s' "$h"
  }

  acquire_one() {
    local remote="$1" rel="${1#/}" dest="$OUT/files/${1#/}"
    local rh rs lh ls match="unknown"
    mkdir -p "$(dirname "$dest")"
    rs="$(remote_size "$remote")"; rh="$(remote_hash "$remote")"

    if scp -q -P "$PORT" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=ask \
      "${USER_NAME}@${HOST}:$remote" "$dest" >>"$OUT/meta/file_acquisition.log" 2>&1; then
      ls="$(wc -c < "$dest" | tr -d ' ')"
      lh="$(host_sha256 "$dest")"
      [[ -n "$rh" && "$rh" == "$lh" ]] && match="true"
      [[ -n "$rh" && "$rh" != "$lh" ]] && match="false"
      {
        echo "remote_path=$remote"; echo "local_path=files/$rel"; echo "status=acquired"
        echo "remote_size=$rs"; echo "local_size=$ls"; echo "remote_sha256=$rh"
        echo "local_sha256=$lh"; echo "hash_match=$match"; echo
      } >> "$OUT/meta/acquired_files_manifest.txt"
    else
      { echo "remote_path=$remote"; echo "status=failed"; echo "remote_size=$rs"; echo "remote_sha256=$rh"; echo; } \
        >> "$OUT/meta/acquired_files_manifest.txt"
    fi
  }

  # Preserve remote filesystem metadata before acquisition. Failures are retained.
  meta_raw="$OUT/meta/remote_file_metadata.txt"; meta_err="$OUT/meta/remote_file_metadata.stderr"; meta_att="$OUT/meta/.metaatt.$$"
  if [[ "$PLATFORM_FAMILY" == "evolved" ]]; then
    meta_cmd="find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f -exec stat -c 'path=%n|type=%F|size=%s|owner=%U|group=%G|mode=%a|inode=%i|mtime=%y|ctime=%z|atime=%x' {} \\; 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && stat -c 'path=%n|type=%F|size=%s|owner=%U|group=%G|mode=%a|inode=%i|mtime=%y|ctime=%z|atime=%x' /usr/lib/libjucomm.so.1"
  else
    meta_cmd="find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f -exec stat -f 'path=%N|type=%HT|size=%z|owner=%Su|group=%Sg|mode=%Lp|inode=%i|mtime=%Sm|ctime=%Sc|atime=%Sa' -t '%Y-%m-%dT%H:%M:%SZ' {} \\; 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && stat -f 'path=%N|type=%HT|size=%z|owner=%Su|group=%Sg|mode=%Lp|inode=%i|mtime=%Sm|ctime=%Sc|atime=%Sa' -t '%Y-%m-%dT%H:%M:%SZ' /usr/lib/libjucomm.so.1"
  fi
  ssh_raw "$(remote_shell_cmd "$meta_cmd")" "$meta_raw" "$meta_err" "$meta_att" || true
  rm -f "$meta_att"

  tmp="$OUT/meta/remote_file_candidates.txt"; err="$OUT/meta/.finderr.$$"; att="$OUT/meta/.findatt.$$"
  ssh_raw "$(remote_shell_cmd "find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && echo /usr/lib/libjucomm.so.1")" "$tmp" "$err" "$att" || true
  rm -f "$err" "$att"

  for f in /var/log/messages /var/log/interactive-commands /var/log/authorization /mfs/var/etc/syslog.conf /mfs/var/etc/syslog.conf0 /var/rundb+ /config/usage_db /var/db/config/usage_db /usr/lib/libjucomm.so.1; do acquire_one "$f"; done
  sort -u "$tmp" | while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    case "$f" in
      /var/log/*) acquire_one "$f" ;;
      /var/tmp/*|/tmp/*|/var/crash/*|/config/*|/root/*|/home/*|/mfs/var/etc/*|/var/db/config/*|/var/rundb+*)
        sz="$(remote_size "$f")"
        [[ "$sz" =~ ^[0-9]+$ ]] && (( sz <= 104857600 )) && acquire_one "$f"
        ;;
    esac
  done
fi


# Existing core dumps are valuable historical memory evidence. Discovery is
# always performed through the CLI; acquisition occurs with --acquire-files.
if [[ "$ACQUIRE_FILES" -eq 1 ]]; then
  log "Acquiring existing core dumps (best effort)"
  core_list="$OUT/meta/existing_core_candidates.txt"
  core_err="$OUT/meta/existing_core_candidates.stderr"
  core_att="$OUT/meta/.coreatt.$$"
  ssh_raw "$(remote_shell_cmd "find /var/core /var/crash -type f -print 2>/dev/null; find /var/tmp -type f \\( -name '*.core' -o -name '*.core.*' -o -name 'core.*' -o -name '*core*.tgz' \\) -print 2>/dev/null")" "$core_list" "$core_err" "$core_att" || true
  rm -f "$core_att"
  sort -u "$core_list" 2>/dev/null | while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # Core files can legitimately exceed the generic 100 MiB cap; acquire them
    # sequentially. Operators should ensure sufficient workstation capacity.
    acquire_one "$f"
  done
fi

# EXPERIMENTAL targeted live-memory acquisition. This does not suspend or alter
# the target process. It reads only readable mapped regions from /proc/PID/mem,
# sequentially, and streams bounded chunks directly to the forensic workstation.
# No Python/Perl/Ruby runtime is required.
if [[ -n "$ACQUIRE_MEMORY" ]]; then
  log "EXPERIMENTAL live-memory acquisition requested for PID(s): $ACQUIRE_MEMORY"
  run_cli "show chassis routing-engine" "80_memory_pre_routing_engine"
  run_cli "show system processes extensive" "81_memory_pre_processes"
  run_cli "show system storage" "82_memory_pre_storage"
  run_cli "show system memory" "83_memory_pre_system_memory"

  # Convert a user-space hexadecimal address to a signed 64-bit Bash integer.
  # Addresses above 0x7fffffffffffffff are skipped conservatively rather than
  # relying on implementation-specific integer overflow behavior.
  hex_to_dec() {
    local h="${1#0x}"
    h="${h#0X}"
    [[ "$h" =~ ^[0-9A-Fa-f]+$ ]] || return 1
    h="${h#${h%%[!0]*}}"; [[ -n "$h" ]] || h=0
    if (( ${#h} > 16 )); then return 1; fi
    if (( ${#h} == 16 )) && [[ "${h:0:1}" =~ [89AaBbCcDdEeFf] ]]; then return 1; fi
    printf '%d' "$((16#$h))"
  }

  # Strip a learned textual login notice from a binary SSH chunk only when the
  # exact notice bytes are present.  The temporary raw chunk is local evidence;
  # no memory data is staged on the router.
  strip_binary_notice() {
    local raw="$1" clean="$2" notice="$OUT/meta/login_notice.txt"
    local n prefix
    if [[ ! -s "$notice" ]]; then mv "$raw" "$clean"; return 0; fi
    n="$(wc -c < "$notice" | tr -d ' ')"
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    if (( n == 0 )); then mv "$raw" "$clean"; return 0; fi
    prefix="$OUT/meta/.binary_prefix.$$"
    dd if="$raw" of="$prefix" bs=1 count="$n" 2>/dev/null || true
    if cmp -s "$notice" "$prefix"; then
      dd if="$raw" of="$clean" bs=1 skip="$n" 2>/dev/null
      rm -f "$raw"
    else
      mv "$raw" "$clean"
    fi
    rm -f "$prefix"
  }

  stream_memory_region() {
    local pid="$1" start_dec="$2" length="$3" outfile="$4" stderr_file="$5"
    local page=4096 chunk_bytes rate_bps pos remain this skip_blocks count_blocks remote
    local raw_chunk clean_chunk chunk_err rc=0 sleep_s
    (( start_dec % page == 0 && length % page == 0 )) || return 97
    chunk_bytes=$((MEMORY_CHUNK_MB * 1024 * 1024))
    rate_bps=$((MEMORY_RATE_MBPS * 1024 * 1024))
    : > "$outfile"; : > "$stderr_file"
    pos="$start_dec"; remain="$length"
    while (( remain > 0 )); do
      this="$chunk_bytes"; (( this > remain )) && this="$remain"
      this=$((this - (this % page))); (( this > 0 )) || return 98
      skip_blocks=$((pos / page)); count_blocks=$((this / page))
      remote="$(remote_shell_cmd "dd if=/proc/$pid/mem bs=$page skip=$skip_blocks count=$count_blocks 2>/dev/null")"
      raw_chunk="$OUT/meta/.memraw.${pid}.$$"
      clean_chunk="$OUT/meta/.memclean.${pid}.$$"
      chunk_err="$OUT/meta/.memerr.${pid}.$$"
      ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$remote" > "$raw_chunk" 2> "$chunk_err" || rc=$?
      cat "$chunk_err" >> "$stderr_file"; rm -f "$chunk_err"
      strip_binary_notice "$raw_chunk" "$clean_chunk"
      cat "$clean_chunk" >> "$outfile"; rm -f "$clean_chunk"
      (( rc == 0 )) || return "$rc"
      pos=$((pos + this)); remain=$((remain - this))
      # Coarse, dependency-free throttling.  One bounded chunk is transferred at
      # a time, then we sleep enough to keep average throughput conservative.
      if (( rate_bps > 0 && remain > 0 )); then
        sleep_s=$(((this + rate_bps - 1) / rate_bps))
        (( sleep_s > 0 )) && sleep "$sleep_s"
      fi
    done
  }

  IFS=',' read -r -a memory_pids <<< "$ACQUIRE_MEMORY"
  for pid in "${memory_pids[@]}"; do
    pdir="$OUT/memory/$pid"; mkdir -p "$pdir/regions"
    map_before="$pdir/map_before.txt"; map_after="$pdir/map_after.txt"
    map_err="$pdir/map.stderr"; map_att="$OUT/meta/.mapatt.$$"
    ssh_raw "$(remote_shell_cmd "cat /proc/$pid/maps 2>/dev/null || cat /proc/$pid/map 2>/dev/null")" "$map_before" "$map_err" "$map_att" || true
    rm -f "$map_att"
    if [[ ! -s "$map_before" ]]; then
      log "PID $pid: no readable /proc memory map; recording as unsupported/denied"
      printf 'pid=%s\nstatus=no_readable_map\n' "$pid" > "$pdir/manifest.txt"
      continue
    fi

    id_out="$pdir/process_identity.txt"; id_err="$pdir/process_identity.stderr"; id_att="$OUT/meta/.idatt.$$"
    ssh_raw "$(remote_shell_cmd "ps -p $pid -o pid,ppid,uid,lstart,args 2>&1 || ps auxww 2>&1 | awk '\\$2 == $pid {print}'")" "$id_out" "$id_err" "$id_att" || true
    rm -f "$id_att"

    printf 'pid=%s\nstarted_utc=%s\nrate_limit_mbps=%s\nstatus=in_progress\n' "$pid" "$(date -u +%FT%TZ)" "$MEMORY_RATE_MBPS" > "$pdir/manifest.txt"

    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      shex=""; ehex=""; perms=""; kind=""; backing=""
      read -r f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12 rest <<< "$line"
      if [[ "$f1" =~ ^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$ ]]; then
        shex="${BASH_REMATCH[1]}"; ehex="${BASH_REMATCH[2]}"; perms="$f2"
        backing="${line#*${f5:-}}"; [[ "$line" == *"[vsyscall]"* ]] && continue
      elif [[ "$f1" =~ ^0[xX][0-9A-Fa-f]+$ && "$f2" =~ ^0[xX][0-9A-Fa-f]+$ ]]; then
        shex="${f1#0x}"; shex="${shex#0X}"; ehex="${f2#0x}"; ehex="${ehex#0X}"
        perms="$f6"; kind="$f12"; backing="$rest"
        [[ "$kind" == "device" || "$kind" == "phys" ]] && continue
      else
        continue
      fi
      [[ "$perms" == *r* ]] || continue
      sdec="$(hex_to_dec "$shex")" || { printf 'region=0x%s-0x%s|status=skipped_address_range\n' "$shex" "$ehex" >> "$pdir/manifest.txt"; continue; }
      edec="$(hex_to_dec "$ehex")" || { printf 'region=0x%s-0x%s|status=skipped_address_range\n' "$shex" "$ehex" >> "$pdir/manifest.txt"; continue; }
      (( edec > sdec )) || continue
      (( sdec % 4096 == 0 && edec % 4096 == 0 )) || continue

      pos="$sdec"; max_chunk=$((MEMORY_CHUNK_MB * 1024 * 1024))
      while (( pos < edec )); do
        length=$((edec - pos)); (( length > max_chunk )) && length="$max_chunk"
        length=$((length - (length % 4096))); (( length > 0 )) || break
        end_dec=$((pos + length))
        printf -v chunk_shex '%x' "$pos"; printf -v chunk_ehex '%x' "$end_dec"
        region="$pdir/regions/${chunk_shex}-${chunk_ehex}.bin"; rerr="$pdir/regions/${chunk_shex}-${chunk_ehex}.stderr"
        log "PID $pid memory: 0x$chunk_shex-0x$chunk_ehex ($length bytes, $perms)"
        rc=0; stream_memory_region "$pid" "$pos" "$length" "$region" "$rerr" || rc=$?
        actual=0; [[ -f "$region" ]] && actual="$(wc -c < "$region" | tr -d ' ')"
        status="acquired"; [[ "$rc" -ne 0 || "$actual" -ne "$length" ]] && status="failed_or_incomplete"
        hash=""; [[ -f "$region" ]] && hash="$(host_sha256 "$region")"
        printf 'region=0x%s-0x%s|expected=%s|actual=%s|perms=%s|type=%s|status=%s|sha256=%s|backing=%s\n' "$chunk_shex" "$chunk_ehex" "$length" "$actual" "$perms" "$kind" "$status" "$hash" "$backing" >> "$pdir/manifest.txt"
        pos="$end_dec"
      done
    done < "$map_before"

    after_err="$pdir/map_after.stderr"; after_att="$OUT/meta/.mapafteratt.$$"
    ssh_raw "$(remote_shell_cmd "cat /proc/$pid/maps 2>/dev/null || cat /proc/$pid/map 2>/dev/null")" "$map_after" "$after_err" "$after_att" || true
    rm -f "$after_att"
    printf 'finished_utc=%s\nstatus=completed_best_effort\n' "$(date -u +%FT%TZ)" >> "$pdir/manifest.txt"
  done

  run_cli "show chassis routing-engine" "84_memory_post_routing_engine"
  run_cli "show system processes extensive" "85_memory_post_processes"
  run_cli "show system storage" "86_memory_post_storage"
  run_cli "show system memory" "87_memory_post_system_memory"
fi

echo "utc_finished=$(date -u +%FT%TZ)" >> "$OUT/meta/manifest.txt"

(
  cd "$OUT" || exit 1
  # Avoid GNU-only sort -z/xargs -0. Junosleuth-generated evidence filenames do
  # not contain newlines, so a portable newline-delimited manifest is sufficient.
  find cli shell raw files memory meta -type f ! -name SHA256SUMS.txt -print | LC_ALL=C sort |
  while IFS= read -r f; do
    printf '%s  %s\n' "$(host_sha256 "$f")" "$f"
  done
) > "$OUT/SHA256SUMS.txt"

log "Collection complete: $OUT"
