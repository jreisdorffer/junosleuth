#!/usr/bin/env bash
# Create and remove benign lab artifacts that resemble forensic indicators seen
# in router intrusion tradecraft. The script does not deploy malware, exploit the
# router, install persistence, or modify system binaries.

set -euo pipefail

HOST=""
USER_NAME="root"
PORT=22
OUT_BASE="./junosleuth-lab-results"
COLLECTOR=""
BATCH=0
CLEANUP_AFTER=0
RUN_MEMORY=0
RUN_MEMORY_ANALYSIS=0
COMMAND=""

usage() {
  cat <<'EOF'
Usage:
  tests/simulate-unc3886-indicators.sh install -H HOST -u USER [options]
  tests/simulate-unc3886-indicators.sh cleanup -H HOST -u USER [options]
  tests/simulate-unc3886-indicators.sh test -H HOST -u USER [options]

Commands:
  install       Create benign lab indicators under /var/tmp and /tmp.
  cleanup       Remove the benign lab indicators and stop the lab worker.
  test          Install indicators, run Junosleuth, and report detection checks.

Options:
  -H, --host HOST       Router management IP or FQDN.
  -u, --user USER       SSH user. Default: root.
  -p, --port PORT       SSH port. Default: 22.
  -o, --output DIR      Local test-result directory.
  --collector PATH      Path to junosleuth.sh. Default: scripts/junosleuth.sh.
  --batch              Pass --batch to the collector and SSH probes.
  --memory             Also acquire memory from the benign lab worker process.
  --memory-analysis    Acquire worker memory and search the dump for a benign
                       memory-resident marker string.
  --cleanup-after      Remove lab indicators after the test run.
  -h, --help           Show this help.

The simulated indicators are text files, timestamps, log lines, and a harmless
sleeping worker process with an optional benign memory marker. They are intended
to exercise collection and detection logic without using weaponized content.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      install|cleanup|test) COMMAND="$1"; shift ;;
      -H|--host) HOST="${2:-}"; shift 2 ;;
      -u|--user) USER_NAME="${2:-}"; shift 2 ;;
      -p|--port) PORT="${2:-}"; shift 2 ;;
      -o|--output) OUT_BASE="${2:-}"; shift 2 ;;
      --collector) COLLECTOR="${2:-}"; shift 2 ;;
      --batch) BATCH=1; shift ;;
      --memory) RUN_MEMORY=1; shift ;;
      --memory-analysis) RUN_MEMORY=1; RUN_MEMORY_ANALYSIS=1; shift ;;
      --cleanup-after) CLEANUP_AFTER=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$COMMAND" ]] || { usage; exit 2; }
  [[ -n "$HOST" ]] || die "missing --host"
  [[ -n "$COLLECTOR" ]] || COLLECTOR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/junosleuth.sh"
}

ssh_opts() {
  printf '%s\n' -T -p "$PORT" -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
  if [[ "$BATCH" -eq 1 ]]; then printf '%s\n' -o BatchMode=yes; fi
}

run_remote_script() {
  local mode="$1"
  mapfile -t opts < <(ssh_opts)
  ssh "${opts[@]}" "${USER_NAME}@${HOST}" "sh -s" -- "$mode" <<'REMOTE'
set -eu
mode="${1:-install}"
base="/var/tmp/.junosleuth-lab/unc3886"
worker="$base/js_unc3886_sim_worker.sh"
pidfile="$base/worker.pid"

stop_worker() {
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    case "$pid" in
      ''|*[!0-9]*) ;;
      *) kill "$pid" 2>/dev/null || true ;;
    esac
  fi
}

case "$mode" in
  cleanup)
    stop_worker
    rm -rf "$base"
    rm -f /tmp/.junosleuth-unc3886-test /var/tmp/.junosleuth-unc3886-test
    command -v logger >/dev/null 2>&1 && logger -t junosleuth-lab "UNC3886_SIM cleanup completed" || true
    ;;
  install)
    mkdir -p "$base/stage" "$base/logs"
    umask 077
    cat > "$base/stage/README.txt" <<'EOF'
Junosleuth benign lab indicator set.
This file is not malware. It is used to validate forensic collection coverage.
marker=UNC3886_SIM_FILE_STAGE
EOF
    cat > "$base/stage/.hidden-loader-note" <<'EOF'
marker=UNC3886_SIM_HIDDEN_FILE
purpose=exercise hidden-file and writable-directory collection
EOF
    cat > "$base/logs/interactive-command-marker.log" <<'EOF'
marker=UNC3886_SIM_INTERACTIVE_COMMAND
purpose=exercise file acquisition and offline detection matching
EOF
    printf 'marker=UNC3886_SIM_TMP_ARTIFACT\n' > /tmp/.junosleuth-unc3886-test
    printf 'marker=UNC3886_SIM_VAR_TMP_ARTIFACT\n' > /var/tmp/.junosleuth-unc3886-test
    touch -t 202001010101 "$base/stage/.hidden-loader-note" 2>/dev/null || true
    cat > "$worker" <<'EOF'
#!/bin/sh
sleep 3600
EOF
    chmod 700 "$worker"
    stop_worker
    JUNOSLEUTH_MEMORY_IMPLANT_MARKER="UNC3886_SIM_MEMORY_IMPLANT_MARKER_BENIGN_DO_NOT_ALERT" sleep 3600 </dev/null >/dev/null 2>&1 &
    echo "$!" > "$pidfile"
    command -v logger >/dev/null 2>&1 && logger -t junosleuth-lab "UNC3886_SIM benign indicator set installed at $base" || true
    echo "indicator_base=$base"
    echo "worker_pid=$(cat "$pidfile")"
    ;;
  *)
    echo "unsupported mode: $mode" >&2
    exit 2
    ;;
esac
REMOTE
}

latest_evidence() {
  find "$OUT_BASE" -maxdepth 1 -type d -name "${HOST}_*" -print 2>/dev/null | sort | tail -1
}

check_contains() {
  local report="$1" name="$2" pattern="$3" path="$4"
  if [[ -f "$path" ]] && grep -Fq "$pattern" "$path"; then
    printf '| %s | pass | `%s` |\n' "$name" "$path" >> "$report"
    return 0
  fi
  printf '| %s | fail | `%s` |\n' "$name" "$path" >> "$report"
  return 1
}

write_memory_analysis() {
  local evidence="$1" pid="$2" marker="$3" report="$4"
  local analysis_file="$OUT_BASE/memory-analysis-report.txt"
  {
    printf 'memory_analysis_utc=%s\n' "$(date -u +%FT%TZ)"
    printf 'evidence=%s\n' "$evidence"
    printf 'pid=%s\n' "$pid"
    printf 'marker=%s\n' "$marker"
    printf '\nmatching_regions:\n'
  } > "$analysis_file"

  if [[ -d "$evidence/memory/$pid/regions" ]] &&
    grep -aR -F -l "$marker" "$evidence/memory/$pid/regions" >> "$analysis_file" 2>/dev/null; then
    printf '| memory marker analysis | pass | `%s` |\n' "$analysis_file" >> "$report"
    return 0
  fi

  printf 'no marker hits\n' >> "$analysis_file"
  printf '| memory marker analysis | fail | `%s` |\n' "$analysis_file" >> "$report"
  return 1
}

run_test() {
  mkdir -p "$OUT_BASE"
  log "Installing benign lab indicators on $HOST"
  install_output="$(run_remote_script install)"
  printf '%s\n' "$install_output"
  worker_pid="$(printf '%s\n' "$install_output" | awk -F= '/^worker_pid=/ {print $2; exit}')"

  args=(-H "$HOST" -u "$USER_NAME" -p "$PORT" -o "$OUT_BASE" --shell --acquire-files)
  [[ "$BATCH" -eq 1 ]] && args+=(--batch)
  if [[ "$RUN_MEMORY" -eq 1 && -n "$worker_pid" ]]; then
    args+=(--acquire-memory "$worker_pid")
  fi

  log "Running Junosleuth collector"
  "$COLLECTOR" "${args[@]}" | tee "$OUT_BASE/indicator-test-collector.log"
  evidence="$(latest_evidence)"
  [[ -n "$evidence" ]] || die "could not locate evidence directory under $OUT_BASE"

  report="$OUT_BASE/indicator-test-report.md"
  {
    printf '# Lab Indicator Test Report\n\n'
    printf '%s\n' "- target: \`$HOST\`"
    printf '%s\n' "- evidence: \`$evidence\`"
    printf '%s\n\n' "- generated_utc: \`$(date -u +%FT%TZ)\`"
    printf '| Check | Result | Evidence |\n'
    printf '|---|---|---|\n'
  } > "$report"

  failures=0
  check_contains "$report" "writable file listing marker" "/var/tmp/.junosleuth-lab/unc3886" "$evidence/shell/69_writable_files_find.txt" || failures=$((failures + 1))
  check_contains "$report" "worker process listing" "sleep 3600" "$evidence/shell/63_ps_auxww.txt" || failures=$((failures + 1))
  check_contains "$report" "messages log marker" "UNC3886_SIM" "$evidence/cli/40_log_messages.txt" || failures=$((failures + 1))
  if [[ -f "$evidence/files/var/tmp/.junosleuth-lab/unc3886/stage/README.txt" ]]; then
    printf '| acquired staged file | pass | `%s` |\n' "$evidence/files/var/tmp/.junosleuth-lab/unc3886/stage/README.txt" >> "$report"
  else
    printf '| acquired staged file | fail | `%s` |\n' "$evidence/files/var/tmp/.junosleuth-lab/unc3886/stage/README.txt" >> "$report"
    failures=$((failures + 1))
  fi
  if [[ "$RUN_MEMORY" -eq 1 ]]; then
    if grep -R "status=acquired" "$evidence/memory/$worker_pid/manifest.txt" >/dev/null 2>&1; then
      printf '| worker memory acquisition | pass | `%s` |\n' "$evidence/memory/$worker_pid/manifest.txt" >> "$report"
    else
      printf '| worker memory acquisition | fail | `%s` |\n' "$evidence/memory/$worker_pid/manifest.txt" >> "$report"
      failures=$((failures + 1))
    fi
    if [[ "$RUN_MEMORY_ANALYSIS" -eq 1 ]]; then
      write_memory_analysis "$evidence" "$worker_pid" "UNC3886_SIM_MEMORY_IMPLANT_MARKER_BENIGN_DO_NOT_ALERT" "$report" || failures=$((failures + 1))
    fi
  fi

  log "Indicator test report: $report"
  if [[ "$CLEANUP_AFTER" -eq 1 ]]; then
    log "Cleaning up benign lab indicators"
    run_remote_script cleanup >/dev/null
  fi
  return "$failures"
}

parse_args "$@"

case "$COMMAND" in
  install)
    run_remote_script install
    ;;
  cleanup)
    run_remote_script cleanup
    ;;
  test)
    run_test
    ;;
esac
