#!/usr/bin/env bash
# Run systematic Junosleuth feature checks against a lab Junos router.

set -euo pipefail

HOST=""
USER_NAME="root"
PORT=22
OUT_BASE="./junosleuth-validation"
COLLECTOR=""
BATCH=0
SKIP_MEMORY=0
SKIP_JMRT=0

usage() {
  cat <<'EOF'
Usage:
  tests/validate-vjunos-features.sh -H HOST -u USER [options]

Options:
  -H, --host HOST       Router management IP or FQDN.
  -u, --user USER       SSH user. Default: root.
  -p, --port PORT       SSH port. Default: 22.
  -o, --output DIR      Validation output directory.
  --collector PATH      Path to junosleuth.sh. Default: scripts/junosleuth.sh.
  --batch              Pass --batch to Junosleuth and SSH probes.
  --skip-jmrt          Do not run the JMRT feature check.
  --skip-memory        Do not run targeted live-memory acquisition.
  -h, --help           Show this help.

The script runs baseline, shell, file acquisition, optional JMRT, and optional
memory checks. It writes a Markdown report and keeps each collector log.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -H|--host) HOST="${2:-}"; shift 2 ;;
      -u|--user) USER_NAME="${2:-}"; shift 2 ;;
      -p|--port) PORT="${2:-}"; shift 2 ;;
      -o|--output) OUT_BASE="${2:-}"; shift 2 ;;
      --collector) COLLECTOR="${2:-}"; shift 2 ;;
      --batch) BATCH=1; shift ;;
      --skip-jmrt) SKIP_JMRT=1; shift ;;
      --skip-memory) SKIP_MEMORY=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$HOST" ]] || die "missing --host"
  [[ -n "$COLLECTOR" ]] || COLLECTOR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/junosleuth.sh"
  [[ -x "$COLLECTOR" ]] || die "collector is not executable: $COLLECTOR"
}

ssh_opts() {
  printf '%s\n' -T -p "$PORT" -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
  if [[ "$BATCH" -eq 1 ]]; then printf '%s\n' -o BatchMode=yes; fi
}

run_remote_shell() {
  local command="$1"
  mapfile -t opts < <(ssh_opts)
  ssh "${opts[@]}" "${USER_NAME}@${HOST}" "sh -c $(single_quote "$command")"
}

single_quote() {
  printf "'"
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

latest_evidence() {
  local before="$1"
  find "$OUT_BASE" -maxdepth 1 -type d -name "${HOST}_*" -newer "$before" -print 2>/dev/null | sort | tail -1
}

count_statuses() {
  local evidence="$1"
  grep -R "^# semantic_status=" "$evidence/cli" "$evidence/shell" 2>/dev/null |
    sed 's/.*semantic_status=//' | sort | uniq -c | sed 's/^/    /' || true
}

record() {
  local feature="$1" result="$2" evidence="$3" note="$4"
  printf '| %s | %s | `%s` | %s |\n' "$feature" "$result" "$evidence" "$note" >> "$REPORT"
}

run_collector_case() {
  local name="$1"; shift
  local stamp log_file rc evidence note result
  local args=(-H "$HOST" -u "$USER_NAME" -p "$PORT" -o "$OUT_BASE")
  [[ "$BATCH" -eq 1 ]] && args+=(--batch)
  args+=("$@")
  stamp="$(mktemp)"
  log_file="$RUN_DIR/${name}.log"
  sleep 1
  log "Running validation case: $name"
  set +e
  "$COLLECTOR" "${args[@]}" >"$log_file" 2>&1
  rc=$?
  set -e
  evidence="$(latest_evidence "$stamp")"
  rm -f "$stamp"
  if [[ "$rc" -eq 0 && -n "$evidence" && -f "$evidence/meta/manifest.txt" && -f "$evidence/SHA256SUMS.txt" ]]; then
    result="pass"
    note="collector exit 0"
  else
    result="fail"
    note="collector exit $rc"
  fi
  record "$name" "$result" "${evidence:-none}" "$note"
  {
    printf '\n## %s\n\n' "$name"
    printf '%s\n' "- result: \`$result\`"
    printf '%s\n' "- log: \`$log_file\`"
    printf '%s\n\n' "- evidence: \`${evidence:-none}\`"
    if [[ -n "${evidence:-}" && -d "$evidence" ]]; then
      printf 'Semantic status counts:\n\n```text\n'
      count_statuses "$evidence"
      printf '```\n'
    fi
  } >> "$DETAILS"
  [[ "$result" == "pass" ]]
}

create_memory_target() {
  run_remote_shell 'sleep 600 >/dev/null 2>&1 & echo $!'
}

cleanup_memory_target() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  run_remote_shell "kill $pid 2>/dev/null || true" >/dev/null 2>&1 || true
}

main() {
  parse_args "$@"
  mkdir -p "$OUT_BASE"
  RUN_DIR="$OUT_BASE/validation-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$RUN_DIR"
  REPORT="$RUN_DIR/summary.md"
  DETAILS="$RUN_DIR/details.md"

  {
    printf '# Junosleuth vJunos Validation Summary\n\n'
    printf '%s\n' "- target: \`$HOST\`"
    printf '%s\n' "- user: \`$USER_NAME\`"
    printf '%s\n\n' "- generated_utc: \`$(date -u +%FT%TZ)\`"
    printf '| Feature | Result | Evidence | Note |\n'
    printf '|---|---|---|---|\n'
  } > "$REPORT"
  : > "$DETAILS"

  failures=0
  run_collector_case baseline || failures=$((failures + 1))
  run_collector_case shell --shell || failures=$((failures + 1))
  run_collector_case file-acquisition --acquire-files || failures=$((failures + 1))
  if [[ "$SKIP_JMRT" -eq 0 ]]; then
    run_collector_case jmrt --jmrt || failures=$((failures + 1))
  fi
  if [[ "$SKIP_MEMORY" -eq 0 ]]; then
    pid="$(create_memory_target | awk '/^[0-9]+$/ {print; exit}')"
    if [[ -n "$pid" ]]; then
      run_collector_case memory --acquire-memory "$pid" --memory-rate-mbps 5 || failures=$((failures + 1))
      cleanup_memory_target "$pid"
    else
      record memory fail none "could not create temporary memory target"
      failures=$((failures + 1))
    fi
  fi

  {
    printf '\n'
    cat "$DETAILS"
  } >> "$REPORT"
  rm -f "$DETAILS"

  log "Validation report: $REPORT"
  if [[ "$failures" -gt 0 ]]; then
    log "Validation completed with $failures failing case(s)"
    exit 1
  fi
  log "Validation completed successfully"
}

main "$@"
