#!/usr/bin/env bash
# Brings up IRIS for Health (Community) in Docker, loads + compiles the HSDemo
# source, runs the smoke gate and the %UnitTest suite, and fails (non-zero exit)
# if anything does not compile or a check fails.
#
# Requirements: Docker (Desktop or Engine) with Compose v2. First run pulls a
# multi-GB image, so it can take several minutes.
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "!! Docker Compose not found. Install Docker Desktop / Docker Engine + Compose." >&2
  exit 1
fi

echo ">> Starting IRIS for Health (Community)... (first run pulls the image)"
$DC up -d

echo ">> Waiting for IRIS to accept ObjectScript sessions..."
ready=0
for i in $(seq 1 60); do
  if printf 'write "ok" halt\n' | $DC exec -T iris iris session IRIS -U USER >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 5
done
if [ "$ready" -ne 1 ]; then
  echo "!! IRIS did not become ready in time. Inspect logs with: $DC logs iris" >&2
  exit 1
fi

echo ">> Loading, compiling, and testing HSDemo..."
set +e
out="$($DC exec -T iris iris session IRIS -U USER < load_and_test.script 2>&1)"
set -e
echo "$out"

echo
if printf '%s' "$out" | grep -q "BUILD_RESULT:PASS"; then
  echo "============================================================"
  echo " BUILD PASSED — code compiled and all checks passed."
  echo " Management Portal: http://localhost:52773/csp/sys/UtilHome.csp"
  echo " Login: _SYSTEM / SYS    Namespace: USER"
  echo " Stop with: $DC down       (add -v to also delete data)"
  echo "============================================================"
  exit 0
else
  echo "!! BUILD FAILED — see the output above." >&2
  exit 1
fi
