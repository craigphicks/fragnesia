#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if command -v ip >/dev/null 2>&1; then
  if ip xfrm state 2>/dev/null | grep -q . || ip xfrm policy 2>/dev/null | grep -q .; then
    echo "This system appears to have IPsec/XFRM state or policy configured."
    echo "Do not disable esp4/esp6 unless you are sure this host is not acting as an IPsec endpoint."
    exit 2
  fi
fi

CONF="/etc/modprobe.d/disable-unused-ipsec.conf"
MODULES=(esp4 esp6 rxrpc)

cat > "${CONF}" <<'EOF'
blacklist esp4
blacklist esp6
blacklist rxrpc

install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF

for mod in "${MODULES[@]}"; do
  modprobe -r "${mod}" 2>/dev/null || true
done

update-initramfs -u

echo "Blacklist applied."
