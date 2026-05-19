#!/usr/bin/env bash
set -u

status="SAFE-ISH"
notes=()

kernel="$(uname -r 2>/dev/null || echo unknown)"

need_root_cmd() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    "$@"
  fi
}

have_modprobe=0
for p in /sbin/modprobe /usr/sbin/modprobe modprobe; do
  if command -v "${p##*/}" >/dev/null 2>&1 || [[ -x "$p" ]]; then
    MODPROBE="$p"
    have_modprobe=1
    break
  fi
done

conf_hits="$(grep -R . /etc/modprobe.d 2>/dev/null | egrep '(^|:)(blacklist|install) (esp4|esp6|rxrpc)\b' || true)"
if [[ -z "${conf_hits}" ]]; then
  status="MITIGATION-MISSING"
  notes+=("no modprobe.d blacklist/install rules found for esp4/esp6/rxrpc")
fi

loaded="$(lsmod 2>/dev/null | egrep '^(esp4|esp6|rxrpc)\b' || true)"
if [[ -n "${loaded}" ]]; then
  status="NEEDS-REBOOT"
  notes+=("one or more modules currently loaded: $(echo "$loaded" | awk '{print $1}' | xargs)")
fi

if [[ "${have_modprobe}" -eq 1 ]]; then
  for m in esp4 esp6 rxrpc; do
    out="$(need_root_cmd "$MODPROBE" -n -v "$m" 2>/dev/null || true)"
    if ! grep -q 'install /bin/false' <<<"$out"; then
      [[ "$status" == "SAFE-ISH" ]] && status="MITIGATION-MISSING"
      notes+=("$m is not effectively blocked by modprobe install rule")
    fi
  done
else
  [[ "$status" == "SAFE-ISH" ]] && status="UNKNOWN"
  notes+=("modprobe not found; could not verify effective install rules")
fi

reboot_line="$(last reboot 2>/dev/null | head -n 1 || true)"
if [[ -z "${reboot_line}" ]]; then
  [[ "$status" == "SAFE-ISH" ]] && status="UNKNOWN"
  notes+=("could not determine reboot history")
fi

if command -v docker >/dev/null 2>&1; then
  cids="$(docker ps -q 2>/dev/null || true)"
  if [[ -n "${cids}" ]]; then
    inspect_lines="$(docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} cap_add={{.HostConfig.CapAdd}} security_opt={{.HostConfig.SecurityOpt}} apparmor={{.AppArmorProfile}}' ${cids} 2>/dev/null || true)"
    weak_lines="$(printf '%s\n' "$inspect_lines" | egrep 'privileged=true|cap_add=\[[^]]|apparmor=unconfined|security_opt=\[[^]]*seccomp=unconfined[^]]*|security_opt=\[[^]]*label=disable[^]]*' || true)"
    if [[ -n "${weak_lines}" ]]; then
      if [[ "$status" == "SAFE-ISH" ]]; then
        status="CONTAINER-HARDENING-WEAK"
      fi
      notes+=("one or more containers have weakened confinement")
    fi
  fi
fi

echo "CLASSIFICATION=${status}"
echo "KERNEL=${kernel}"
echo "REBOOT=$(echo "$reboot_line" | sed 's/[[:space:]]\+/ /g')"

echo
echo "MODULE_RULES:"
if [[ -n "${conf_hits}" ]]; then
  printf '%s\n' "$conf_hits"
else
  echo "(none found)"
fi

echo
echo "LOADED_MODULES:"
if [[ -n "${loaded}" ]]; then
  printf '%s\n' "$loaded"
else
  echo "(none)"
fi

echo
echo "NOTES:"
if [[ "${#notes[@]}" -eq 0 ]]; then
  echo "- mitigation looks active; still patch kernel when Debian releases a fix"
else
  for n in "${notes[@]}"; do
    echo "- $n"
  done
fi

if command -v docker >/dev/null 2>&1; then
  echo
  echo "DOCKER_CONTAINERS:"
  if [[ -n "${cids:-}" ]]; then
    printf '%s\n' "${inspect_lines:-}"
  else
    echo "(no running containers)"
  fi
fi