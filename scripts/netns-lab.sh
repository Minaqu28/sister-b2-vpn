#!/usr/bin/env bash

# Penggunaan:
#   sudo ./scripts/netns-lab.sh up        bangun topologi + jalankan VPN (pengujian otomatis)
#   sudo ./scripts/netns-lab.sh topology  bangun topologi SAJA, VPN dinyalakan manual (untuk video)
#   sudo ./scripts/netns-lab.sh down      hentikan VPN + hapus topologi
#   sudo ./scripts/netns-lab.sh status    tampilkan alamat dan route
#   sudo ./scripts/netns-lab.sh logs      tampilkan log kedua endpoint
#   sudo ./scripts/netns-lab.sh shell NS  buka shell di dalam namespace

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="${LAB_DIR:-/tmp/sister-vpn-lab}"


BIN="./bin/vpn"
KEY="secret.key"
CONF_A="configs/endpoint-a.conf"
CONF_B="configs/endpoint-b.conf"

LOG_A="$LAB_DIR/endpoint-a.log"
LOG_B="$LAB_DIR/endpoint-b.log"

NS_A=vpn-a
NS_B=vpn-b
NS_R=vpn-r
NS_LA=lan-a
NS_LB=lan-b
ALL_NS=("$NS_A" "$NS_B" "$NS_R" "$NS_LA" "$NS_LB")

PORT=51820
MTU=1400

# Alamat underlay (jaringan "publik/untrusted" yang dilewati UDP terenkripsi)
WAN_A=10.10.1.2
WAN_A_GW=10.10.1.1
WAN_B=10.10.2.2
WAN_B_GW=10.10.2.1

# Alamat overlay (di dalam tunnel)
TUN_A=10.9.0.1
TUN_B=10.9.0.2
TUN_NET=10.9.0.0/24

# LAN di belakang tiap endpoint
LAN_A_NET=192.168.1.0/24
LAN_A_GW=192.168.1.1
LAN_A_HOST=192.168.1.10
LAN_B_NET=192.168.2.0/24
LAN_B_GW=192.168.2.1
LAN_B_HOST=192.168.2.10

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mXXX\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "skrip ini harus dijalankan sebagai root (gunakan sudo)"
}

require_tun() {
  [ -c /dev/net/tun ] || die "/dev/net/tun tidak ada; jalankan: modprobe tun"
}

build() {
  command -v go >/dev/null || die "go tidak ditemukan di PATH"
  mkdir -p "$LAB_DIR" "$REPO_DIR/bin"
  log "membangun binary VPN ke $BIN"
  ( cd "$REPO_DIR" && go build -o "$BIN" ./cmd/vpn )
}

genkey() {
  if [ -f "$REPO_DIR/$KEY" ]; then
    log "memakai pre-shared key yang sudah ada di $KEY"
  else
    log "membuat pre-shared key baru"
    ( cd "$REPO_DIR" && "$BIN" genkey -out "$KEY" )
  fi
}

topology_up() {
  log "membuat network namespace: ${ALL_NS[*]}"
  for ns in "${ALL_NS[@]}"; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
  done

  log "membuat veth: lan-a <-> vpn-a <-> vpn-r <-> vpn-b <-> lan-b"
  ip link add la-host type veth peer name a-lan
  ip link add a-wan   type veth peer name r-a
  ip link add b-wan   type veth peer name r-b
  ip link add lb-host type veth peer name b-lan

  ip link set la-host netns "$NS_LA"
  ip link set a-lan   netns "$NS_A"
  ip link set a-wan   netns "$NS_A"
  ip link set r-a     netns "$NS_R"
  ip link set r-b     netns "$NS_R"
  ip link set b-wan   netns "$NS_B"
  ip link set b-lan   netns "$NS_B"
  ip link set lb-host netns "$NS_LB"

  log "memasang alamat underlay (dua subnet berbeda, dipisahkan router)"
  ip netns exec "$NS_A" ip addr add "$WAN_A/24" dev a-wan
  ip netns exec "$NS_A" ip link set a-wan up
  ip netns exec "$NS_R" ip addr add "$WAN_A_GW/24" dev r-a
  ip netns exec "$NS_R" ip link set r-a up

  ip netns exec "$NS_B" ip addr add "$WAN_B/24" dev b-wan
  ip netns exec "$NS_B" ip link set b-wan up
  ip netns exec "$NS_R" ip addr add "$WAN_B_GW/24" dev r-b
  ip netns exec "$NS_R" ip link set r-b up

  # Router meneruskan antar kedua subnet underlay.
  ip netns exec "$NS_R" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$NS_A" ip route add "10.10.2.0/24" via "$WAN_A_GW" dev a-wan
  ip netns exec "$NS_B" ip route add "10.10.1.0/24" via "$WAN_B_GW" dev b-wan

  log "memasang LAN di belakang tiap endpoint"
  ip netns exec "$NS_A" ip addr add "$LAN_A_GW/24" dev a-lan
  ip netns exec "$NS_A" ip link set a-lan up
  ip netns exec "$NS_LA" ip addr add "$LAN_A_HOST/24" dev la-host
  ip netns exec "$NS_LA" ip link set la-host up
  ip netns exec "$NS_LA" ip route add default via "$LAN_A_GW"

  ip netns exec "$NS_B" ip addr add "$LAN_B_GW/24" dev b-lan
  ip netns exec "$NS_B" ip link set b-lan up
  ip netns exec "$NS_LB" ip addr add "$LAN_B_HOST/24" dev lb-host
  ip netns exec "$NS_LB" ip link set lb-host up
  ip netns exec "$NS_LB" ip route add default via "$LAN_B_GW"
}

topology_down() {
  for ns in "${ALL_NS[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  for l in la-host a-lan a-wan r-a r-b b-wan b-lan lb-host; do
    ip link del "$l" 2>/dev/null || true
  done
}

# -------------------------------------------------------------------- VPN ---

start_a() {
  log "menjalankan endpoint A (server) di namespace $NS_A"
  ( cd "$REPO_DIR" && ip netns exec "$NS_A" "$BIN" server -config "$CONF_A" ) >>"$LOG_A" 2>&1 &
  echo $! > "$LAB_DIR/a.pid"
}

start_b() {
  log "menjalankan endpoint B (client) di namespace $NS_B"
  ( cd "$REPO_DIR" && ip netns exec "$NS_B" "$BIN" client -config "$CONF_B" ) >>"$LOG_B" 2>&1 &
  echo $! > "$LAB_DIR/b.pid"
}

start_vpn() {
  : > "$LOG_A"
  : > "$LOG_B"
  start_a
  sleep 0.5
  start_b
}

wait_ready() {
  log "menunggu tunnel siap"
  for _ in $(seq 1 50); do
    if ip netns exec "$NS_A" ip link show vpn0 >/dev/null 2>&1 &&
       ip netns exec "$NS_B" ip link show vpn0 >/dev/null 2>&1; then
      if ip netns exec "$NS_B" ping -c 1 -W 1 "$TUN_A" >/dev/null 2>&1; then
        log "tunnel hidup: $TUN_A <-> $TUN_B"
        return 0
      fi
    fi
    sleep 0.3
  done

  warn "tunnel belum merespons, isi log:"
  tail -n 40 "$LOG_A" "$LOG_B" >&2 || true
  return 1
}

stop_vpn() {
  for p in "$LAB_DIR/a.pid" "$LAB_DIR/b.pid"; do
    [ -f "$p" ] || continue
    pid="$(cat "$p")"
    kill "$pid" 2>/dev/null || true
    rm -f "$p"
  done
  pkill -f "$BIN " 2>/dev/null || true
  sleep 0.3
}


cmd_up() {
  require_root
  require_tun
  log "membersihkan sisa lab sebelumnya"
  stop_vpn
  topology_down
  build
  genkey
  topology_up
  start_vpn
  wait_ready
  log "lab siap; kedua endpoint sudah berjalan. Alur pengujian: README.md"
}


cmd_topology() {
  require_root
  require_tun
  log "membersihkan sisa lab sebelumnya"
  stop_vpn
  topology_down
  build
  genkey
  topology_up

  cat <<EOF

$(printf '\033[1;32m')Topologi siap. VPN BELUM dinyalakan.$(printf '\033[0m')

Jalankan dua perintah berikut di dua terminal terpisah, dari root repositori:

$(printf '\033[1;36m')── TERMINAL 1: endpoint A (server) ──$(printf '\033[0m')
  sudo ip netns exec $NS_A $BIN server -config $CONF_A

$(printf '\033[1;36m')── TERMINAL 2: endpoint B (client) ──$(printf '\033[0m')
  sudo ip netns exec $NS_B $BIN client -config $CONF_B

EOF
}

cmd_down() {
  require_root
  log "menghentikan endpoint VPN"
  stop_vpn
  log "menghapus topologi"
  topology_down
  log "selesai"
}

cmd_status() {
  require_root
  for ns in "${ALL_NS[@]}"; do
    printf '\n\033[1;36m--- namespace %s ---\033[0m\n' "$ns"
    ip netns exec "$ns" ip -brief addr show
    echo "routes:"
    ip netns exec "$ns" ip route show
  done
}

cmd_logs() {
  printf '\n\033[1;36m--- log endpoint A ---\033[0m\n'
  cat "$LOG_A" 2>/dev/null || echo "(belum ada)"
  printf '\n\033[1;36m--- log endpoint B ---\033[0m\n'
  cat "$LOG_B" 2>/dev/null || echo "(belum ada)"
}

cmd_shell() {
  require_root
  local ns="${1:-}"
  [ -n "$ns" ] || die "sebutkan namespace: ${ALL_NS[*]}"
  exec ip netns exec "$ns" "${SHELL:-/bin/bash}"
}

case "${1:-}" in
  up)        cmd_up ;;
  topology)  cmd_topology ;;
  down)      cmd_down ;;
  status) cmd_status ;;
  logs)   cmd_logs ;;
  shell)  shift; cmd_shell "$@" ;;
  *)
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
