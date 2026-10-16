#!/usr/bin/env bash
# Build-verify every sidecar image. Run on a host with docker installed.
#
#   cd docker
#   ./verify.sh                  # build + probe /health on all 10
#   ./verify.sh qiling clamav    # subset
#
# Each service:
#   1. docker build (fails fast on missing pip packages)
#   2. docker run --rm -p <ephem>:5000 the image for 20s
#   3. curl http://localhost:<ephem>/health → expect 200 {ok:true}
#   4. tear it down

set -euo pipefail

cd "$(dirname "$0")/sidecars"

# service → (dockerfile, build arg SERVICE, build arg TOOLS)
declare -A SERVICES=(
  [qiling]="Dockerfile.python qiling_service qiling"
  [speakeasy]="Dockerfile.python speakeasy_service speakeasy-emulator"
  [thug]="Dockerfile.python thug_service thug"
  [box_js]="Dockerfile.boxjs - -"
  [mobsf]="Dockerfile.python mobsf_service requests"
  [quark_engine]="Dockerfile.python quark_service quark-engine"
  [clamav]="Dockerfile.clamav - -"
  [suricata]="Dockerfile.suricata - -"
  [hfinger]="Dockerfile.python hfinger_service hfinger"
  [stringsifter]="Dockerfile.python stringsifter_service stringsifter"
)

TARGETS=("$@")
if [ "${#TARGETS[@]}" -eq 0 ]; then
  TARGETS=("${!SERVICES[@]}")
fi

PASS=()
FAIL=()

for svc in "${TARGETS[@]}"; do
  spec="${SERVICES[$svc]:-}"
  if [ -z "$spec" ]; then
    echo "  [SKIP] $svc — unknown service"
    continue
  fi
  read -r dockerfile service_arg tools_arg <<< "$spec"

  echo
  echo "═══ $svc ═══"
  tag="recon-sidecar-${svc}:verify"
  build_cmd=(docker build -f "$dockerfile" -t "$tag")
  if [ "$service_arg" != "-" ]; then
    build_cmd+=(--build-arg "SERVICE=$service_arg" --build-arg "TOOLS=$tools_arg")
  fi
  build_cmd+=(.)
  if ! "${build_cmd[@]}"; then
    FAIL+=("$svc (build)")
    continue
  fi

  # Pick an ephemeral port
  port=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
)
  cid=$(docker run -d --rm -p "${port}:5000" --name "recon-verify-${svc}" "$tag")

  # Wait up to 25s for /health
  ok=0
  for _ in $(seq 1 25); do
    if curl -sf "http://127.0.0.1:${port}/health" >/dev/null; then
      ok=1
      break
    fi
    sleep 1
  done

  if [ "$ok" -eq 1 ]; then
    PASS+=("$svc")
    echo "  [PASS] $svc"
  else
    FAIL+=("$svc (health)")
    echo "  [FAIL] $svc — /health never came up"
    docker logs "$cid" 2>&1 | tail -20
  fi

  docker stop "$cid" >/dev/null 2>&1 || true
done

echo
echo "═══ Summary ═══"
echo "  passed: ${#PASS[@]} — ${PASS[*]:-}"
if [ "${#FAIL[@]}" -gt 0 ]; then
  echo "  failed: ${#FAIL[@]} — ${FAIL[*]}"
  exit 1
fi
