#!/usr/bin/env bash
# Deploy and manage a disposable vJunos-router KVM lab on a remote Linux host.
#
# The script keeps the Junos image private to the remote libvirt host by
# default. It creates a qcow2 overlay, attaches management to libvirt NAT, adds
# isolated data-plane networks, generates temporary SSH credentials on the lab
# host, and configures the fresh vJunos instance over the serial console.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=""

REMOTE_HOST="${REMOTE_HOST:-vjunos-lab-host}"
LOCAL_IMAGE="${LOCAL_IMAGE:-}"
VM_NAME="${VM_NAME:-junosleuth-vjunos}"
REMOTE_BASE_IMAGE="${REMOTE_BASE_IMAGE:-/var/lib/libvirt/images/vJunos-router-26.2R1.7-base.qcow2}"
REMOTE_OVERLAY_IMAGE="${REMOTE_OVERLAY_IMAGE:-/var/lib/libvirt/images/${VM_NAME}-live.qcow2}"
VCPUS="${VCPUS:-4}"
RAM_MB="${RAM_MB:-8192}"
MGMT_NETWORK="${MGMT_NETWORK:-default}"
DATA_NETWORK_0="${DATA_NETWORK_0:-vjunos-ge000}"
DATA_NETWORK_1="${DATA_NETWORK_1:-vjunos-ge001}"
MGMT_MAC="${MGMT_MAC:-52:54:00:06:1f:a5}"
DATA_MAC_0="${DATA_MAC_0:-52:54:00:3e:b5:2e}"
DATA_MAC_1="${DATA_MAC_1:-52:54:00:de:dd:0e}"
REMOTE_STATE_DIR="${REMOTE_STATE_DIR:-/var/lib/junosleuth-lab}"
REMOTE_ROUTER_KEY="${REMOTE_ROUTER_KEY:-${REMOTE_STATE_DIR}/credentials/router_ed25519}"
REMOTE_ROUTER_PASSWORD_FILE="${REMOTE_ROUTER_PASSWORD_FILE:-${REMOTE_STATE_DIR}/credentials/router_password}"
REMOTE_ROUTER_HASH_FILE="${REMOTE_ROUTER_HASH_FILE:-${REMOTE_STATE_DIR}/credentials/router_password_hash}"
REMOTE_ROUTER_SSH_CONFIG="${REMOTE_ROUTER_SSH_CONFIG:-${REMOTE_STATE_DIR}/router_ssh_config}"
REMOTE_ROUTER_KNOWN_HOSTS="${REMOTE_ROUTER_KNOWN_HOSTS:-${REMOTE_STATE_DIR}/router_known_hosts}"
REMOVE_BASE_IMAGE=0
SKIP_CONFIG=0

usage() {
  cat <<'EOF'
Usage:
  tests/vjunos-lab-deploy.sh [options] install-prereqs
  tests/vjunos-lab-deploy.sh [options] deploy
  tests/vjunos-lab-deploy.sh [options] configure
  tests/vjunos-lab-deploy.sh [options] status
  tests/vjunos-lab-deploy.sh [options] reset
  tests/vjunos-lab-deploy.sh [options] revert

Commands:
  install-prereqs  Install KVM/libvirt tooling on the remote Ubuntu/Debian host.
  deploy           Upload image if needed, create networks, create VM, configure SSH.
  configure        Configure an already running fresh vJunos VM over serial console.
  status           Show VM, network, and management-IP status.
  reset            Delete the overlay and VM, then redeploy from the base image.
  revert           Remove the lab VM, overlay, private networks, and generated keys.

Options:
  --env FILE             Load settings from a shell env file.
  --remote HOST          SSH target for the KVM host. Default: vjunos-lab-host.
  --image FILE           Local vJunos qcow2 image to upload if remote base is absent.
  --vm-name NAME         Libvirt domain name. Default: junosleuth-vjunos.
  --remote-base PATH     Remote base qcow2 path.
  --remote-overlay PATH  Remote overlay qcow2 path.
  --ram MB              Guest memory. Default: 8192.
  --vcpus N             Guest vCPU count. Default: 4.
  --skip-config         Deploy the VM but skip serial-console configuration.
  --remove-base-image   With revert, also remove the uploaded base image.
  -h, --help            Show this help.

Security model:
  The vJunos management interface is attached to libvirt NAT on the remote host.
  No public port forward is created. Access the router from the KVM host or
  through an SSH jump to the KVM host.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

load_env() {
  [[ -z "$ENV_FILE" ]] && return 0
  [[ -f "$ENV_FILE" ]] || die "env file not found: $ENV_FILE"
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env) ENV_FILE="${2:-}"; shift 2 ;;
      --remote) REMOTE_HOST="${2:-}"; shift 2 ;;
      --image) LOCAL_IMAGE="${2:-}"; shift 2 ;;
      --vm-name) VM_NAME="${2:-}"; shift 2 ;;
      --remote-base) REMOTE_BASE_IMAGE="${2:-}"; shift 2 ;;
      --remote-overlay) REMOTE_OVERLAY_IMAGE="${2:-}"; shift 2 ;;
      --ram) RAM_MB="${2:-}"; shift 2 ;;
      --vcpus) VCPUS="${2:-}"; shift 2 ;;
      --skip-config) SKIP_CONFIG=1; shift ;;
      --remove-base-image) REMOVE_BASE_IMAGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      install-prereqs|deploy|configure|status|reset|revert) COMMAND="$1"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  COMMAND="${COMMAND:-}"
  [[ -n "$COMMAND" ]] || { usage; exit 2; }
}

sq() {
  printf "'"
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

remote_prefix() {
  printf 'VM_NAME=%s ' "$(sq "$VM_NAME")"
  printf 'REMOTE_BASE_IMAGE=%s ' "$(sq "$REMOTE_BASE_IMAGE")"
  printf 'REMOTE_OVERLAY_IMAGE=%s ' "$(sq "$REMOTE_OVERLAY_IMAGE")"
  printf 'VCPUS=%s ' "$(sq "$VCPUS")"
  printf 'RAM_MB=%s ' "$(sq "$RAM_MB")"
  printf 'MGMT_NETWORK=%s ' "$(sq "$MGMT_NETWORK")"
  printf 'DATA_NETWORK_0=%s ' "$(sq "$DATA_NETWORK_0")"
  printf 'DATA_NETWORK_1=%s ' "$(sq "$DATA_NETWORK_1")"
  printf 'MGMT_MAC=%s ' "$(sq "$MGMT_MAC")"
  printf 'DATA_MAC_0=%s ' "$(sq "$DATA_MAC_0")"
  printf 'DATA_MAC_1=%s ' "$(sq "$DATA_MAC_1")"
  printf 'REMOTE_STATE_DIR=%s ' "$(sq "$REMOTE_STATE_DIR")"
  printf 'REMOTE_ROUTER_KEY=%s ' "$(sq "$REMOTE_ROUTER_KEY")"
  printf 'REMOTE_ROUTER_PASSWORD_FILE=%s ' "$(sq "$REMOTE_ROUTER_PASSWORD_FILE")"
  printf 'REMOTE_ROUTER_HASH_FILE=%s ' "$(sq "$REMOTE_ROUTER_HASH_FILE")"
  printf 'REMOTE_ROUTER_SSH_CONFIG=%s ' "$(sq "$REMOTE_ROUTER_SSH_CONFIG")"
  printf 'REMOTE_ROUTER_KNOWN_HOSTS=%s ' "$(sq "$REMOTE_ROUTER_KNOWN_HOSTS")"
  printf 'REMOVE_BASE_IMAGE=%s ' "$(sq "$REMOVE_BASE_IMAGE")"
}

remote_bash() {
  local prefix
  prefix="$(remote_prefix)"
  ssh "$REMOTE_HOST" "$prefix bash -s"
}

install_prereqs() {
  log "Installing KVM/libvirt prerequisites on $REMOTE_HOST"
  remote_bash <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients virtinst bridge-utils genisoimage expect openssl
systemctl enable --now libvirtd || systemctl enable --now virtqemud || true
virsh net-start default >/dev/null 2>&1 || true
virsh net-autostart default >/dev/null 2>&1 || true
REMOTE
}

upload_image_if_needed() {
  if ssh "$REMOTE_HOST" "test -s $(sq "$REMOTE_BASE_IMAGE")"; then
    log "Remote base image already exists: $REMOTE_BASE_IMAGE"
    return 0
  fi
  [[ -n "$LOCAL_IMAGE" ]] || die "remote base image is missing and --image was not provided"
  [[ -f "$LOCAL_IMAGE" ]] || die "local image not found: $LOCAL_IMAGE"
  log "Uploading vJunos base image to $REMOTE_HOST:$REMOTE_BASE_IMAGE"
  ssh "$REMOTE_HOST" "mkdir -p $(sq "$(dirname "$REMOTE_BASE_IMAGE")")"
  scp "$LOCAL_IMAGE" "$REMOTE_HOST:$REMOTE_BASE_IMAGE"
}

create_remote_lab() {
  log "Creating vJunos lab VM on $REMOTE_HOST"
  remote_bash <<'REMOTE'
set -euo pipefail

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing remote command: $1" >&2; exit 1; }; }
require virsh
require qemu-img
require virt-install
require expect
require ssh-keygen
require openssl

virsh net-info "$MGMT_NETWORK" >/dev/null
virsh net-start "$MGMT_NETWORK" >/dev/null 2>&1 || true
virsh net-autostart "$MGMT_NETWORK" >/dev/null 2>&1 || true

create_isolated_net() {
  local name="$1" bridge="$2"
  if ! virsh net-info "$name" >/dev/null 2>&1; then
    tmp="$(mktemp)"
    cat > "$tmp" <<XML
<network>
  <name>${name}</name>
  <bridge name='${bridge}' stp='on' delay='0'/>
</network>
XML
    virsh net-define "$tmp" >/dev/null
    rm -f "$tmp"
  fi
  virsh net-start "$name" >/dev/null 2>&1 || true
  virsh net-autostart "$name" >/dev/null 2>&1 || true
}

create_isolated_net "$DATA_NETWORK_0" "vj-ge000"
create_isolated_net "$DATA_NETWORK_1" "vj-ge001"

if ! test -s "$REMOTE_BASE_IMAGE"; then
  echo "remote base image not found: $REMOTE_BASE_IMAGE" >&2
  exit 1
fi

if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  echo "domain already exists: $VM_NAME"
else
  rm -f "$REMOTE_OVERLAY_IMAGE"
  qemu-img create -f qcow2 -F qcow2 -b "$REMOTE_BASE_IMAGE" "$REMOTE_OVERLAY_IMAGE" >/dev/null
  virt-install \
    --name "$VM_NAME" \
    --memory "$RAM_MB" \
    --vcpus "$VCPUS" \
    --cpu host-passthrough \
    --import \
    --disk "path=$REMOTE_OVERLAY_IMAGE,format=qcow2,bus=virtio" \
    --network "network=$MGMT_NETWORK,model=virtio,mac=$MGMT_MAC" \
    --network "network=$DATA_NETWORK_0,model=virtio,mac=$DATA_MAC_0" \
    --network "network=$DATA_NETWORK_1,model=virtio,mac=$DATA_MAC_1" \
    --os-variant freebsd13.0 \
    --graphics none \
    --console pty,target_type=serial \
    --noautoconsole \
    --boot hd \
    --events on_reboot=restart \
    --sysinfo "system.product=VM-VMX,system.family=lab" >/dev/null
fi

virsh start "$VM_NAME" >/dev/null 2>&1 || true
REMOTE
}

configure_router() {
  log "Configuring vJunos over the remote serial console"
  remote_bash <<'REMOTE'
set -euo pipefail

mkdir -p "$REMOTE_STATE_DIR"
chmod 700 "$REMOTE_STATE_DIR"
mkdir -p "$(dirname "$REMOTE_ROUTER_KEY")"
chmod 700 "$(dirname "$REMOTE_ROUTER_KEY")"

if [[ ! -s "$REMOTE_ROUTER_KEY" ]]; then
  ssh-keygen -q -t ed25519 -N "" -C "junosleuth-vjunos-test" -f "$REMOTE_ROUTER_KEY"
fi

if [[ ! -s "$REMOTE_ROUTER_PASSWORD_FILE" ]]; then
  tr -dc 'A-Za-z0-9_+=' < /dev/urandom | head -c 32 > "$REMOTE_ROUTER_PASSWORD_FILE"
  chmod 600 "$REMOTE_ROUTER_PASSWORD_FILE"
fi

password="$(cat "$REMOTE_ROUTER_PASSWORD_FILE")"
openssl passwd -6 "$password" > "$REMOTE_ROUTER_HASH_FILE"
chmod 600 "$REMOTE_ROUTER_HASH_FILE"
pubkey="$(cat "${REMOTE_ROUTER_KEY}.pub")"
hash="$(cat "$REMOTE_ROUTER_HASH_FILE")"

for _ in $(seq 1 90); do
  if virsh domstate "$VM_NAME" 2>/dev/null | grep -qi running; then
    break
  fi
  sleep 2
done

expect_file="$(mktemp)"
cat > "$expect_file" <<'EXPECT'
set timeout 240
set vm $env(VM_NAME)
set pubkey $env(VJUNOS_PUBKEY)
set hash $env(VJUNOS_HASH)
spawn virsh console $vm
expect {
  -re "Escape character.*" {}
  timeout {}
}
send "\r"
expect {
  -re "login:" { send "root\r" }
  -re "(%|#|>) $" {}
  timeout { send "\r"; exp_continue }
}
expect {
  -re "(%|#|>) $" {}
  timeout {}
}
send "cli\r"
expect {
  -re "> $" {}
  -re "# $" {}
  timeout {}
}
send "configure\r"
expect {
  -re "# $" {}
  timeout {}
}
send "set system host-name $vm\r"
send "set system services ssh root-login allow\r"
send "set system root-authentication encrypted-password \"$hash\"\r"
send "set system root-authentication ssh-ed25519 \"$pubkey\"\r"
send "set interfaces fxp0 unit 0 family inet dhcp\r"
send "delete chassis auto-image-upgrade\r"
send "commit\r"
expect {
  -re "commit complete" {}
  -re "error:" { exit 2 }
  timeout { exit 3 }
}
send "exit\r"
expect {
  -re "> $" {}
  timeout {}
}
send "exit\r"
send "\035"
expect eof
EXPECT

VJUNOS_PUBKEY="$pubkey" VJUNOS_HASH="$hash" expect "$expect_file"
rm -f "$expect_file"

ip=""
for _ in $(seq 1 90); do
  ip="$(virsh domifaddr "$VM_NAME" --source lease 2>/dev/null | awk '/ipv4/ {sub("/.*","",$4); print $4; exit}')"
  [[ -n "$ip" ]] && break
  sleep 2
done

[[ -n "$ip" ]] || { echo "could not determine vJunos management IP" >&2; exit 1; }

cat > "$REMOTE_ROUTER_SSH_CONFIG" <<EOF
Host ${VM_NAME}
  HostName ${ip}
  User root
  IdentityFile ${REMOTE_ROUTER_KEY}
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile ${REMOTE_ROUTER_KNOWN_HOSTS}
EOF
chmod 600 "$REMOTE_ROUTER_SSH_CONFIG"

echo "target_ip=$ip"
echo "remote_ssh_config=$REMOTE_ROUTER_SSH_CONFIG"
echo "remote_private_key=$REMOTE_ROUTER_KEY"
echo "router_ssh_command=ssh -F $REMOTE_ROUTER_SSH_CONFIG $VM_NAME"
REMOTE
}

status_lab() {
  remote_bash <<'REMOTE'
set -euo pipefail
echo "domain:"
virsh dominfo "$VM_NAME" 2>/dev/null || true
echo
echo "interfaces:"
virsh domifaddr "$VM_NAME" --source lease 2>/dev/null || true
echo
echo "networks:"
virsh net-list --all | sed -n '1,80p'
echo
echo "ssh config:"
test -f "$REMOTE_ROUTER_SSH_CONFIG" && cat "$REMOTE_ROUTER_SSH_CONFIG" || true
echo
echo "router ssh command:"
test -f "$REMOTE_ROUTER_SSH_CONFIG" && printf 'ssh -F %s %s\n' "$REMOTE_ROUTER_SSH_CONFIG" "$VM_NAME" || true
REMOTE
}

revert_lab() {
  log "Reverting vJunos lab resources on $REMOTE_HOST"
  remote_bash <<'REMOTE'
set -euo pipefail
virsh shutdown "$VM_NAME" >/dev/null 2>&1 || true
sleep 5
virsh destroy "$VM_NAME" >/dev/null 2>&1 || true
virsh undefine "$VM_NAME" >/dev/null 2>&1 || true

for net in "$DATA_NETWORK_0" "$DATA_NETWORK_1"; do
  virsh net-destroy "$net" >/dev/null 2>&1 || true
  virsh net-undefine "$net" >/dev/null 2>&1 || true
done

rm -f "$REMOTE_OVERLAY_IMAGE"
rm -f "$REMOTE_ROUTER_KEY" "${REMOTE_ROUTER_KEY}.pub" "$REMOTE_ROUTER_PASSWORD_FILE" "$REMOTE_ROUTER_HASH_FILE" "$REMOTE_ROUTER_SSH_CONFIG" "$REMOTE_ROUTER_KNOWN_HOSTS"
rmdir "$(dirname "$REMOTE_ROUTER_KEY")" "$REMOTE_STATE_DIR" >/dev/null 2>&1 || true

if [[ "$REMOVE_BASE_IMAGE" == "1" ]]; then
  rm -f "$REMOTE_BASE_IMAGE"
fi

echo "reverted=$VM_NAME"
REMOTE
}

parse_args "$@"
load_env

case "$COMMAND" in
  install-prereqs)
    install_prereqs
    ;;
  deploy)
    upload_image_if_needed
    create_remote_lab
    if [[ "$SKIP_CONFIG" -eq 0 ]]; then
      configure_router
    fi
    status_lab
    ;;
  configure)
    configure_router
    ;;
  status)
    status_lab
    ;;
  reset)
    revert_lab
    upload_image_if_needed
    create_remote_lab
    if [[ "$SKIP_CONFIG" -eq 0 ]]; then
      configure_router
    fi
    status_lab
    ;;
  revert)
    revert_lab
    ;;
esac
