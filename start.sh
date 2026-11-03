#!/usr/bin/env bash
# Ensure Docker Desktop CLI is available on macOS
if [[ "$OSTYPE" == darwin* ]]; then
  export PATH="/Applications/Docker.app/Contents/Resources/bin:/usr/local/bin:$PATH"
fi

# Starts the Project Quarry demo in Docker on this computer (macOS / Linux).
#
#   bash start.sh [--port 5075] [--image IMAGE] [--no-pull] [--build] [--no-cert-export]
#                 [--relax-strict-tls] [--no-browser]
#
# - Checks Docker is running.
# - If the certs folder is empty, exports your network's HTTPS-inspection CA (for example Cisco
#   Secure Access) so the container can reach OpenAI / AI Defense. Skipped when not inspected.
# - Pulls the latest image, replaces any existing container, mounts this folder's certs folder
#   by full path, waits for the app, then opens http://127.0.0.1:<port>.
# Saved API keys live in the "quarry-demo-data" Docker volume and survive restarts and upgrades.
set -euo pipefail

IMAGE="ghcr.io/slblack/project-quarry-demo:latest"
PORT=5075
PULL=1
BUILD=0
CERT_EXPORT=1
RELAX=0
BROWSER=1
NAME="project-quarry-demo"
VOLUME="quarry-demo-data"
ROOT="$(cd "$(dirname "$0")" && pwd)"
CERTS="$ROOT/certs"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --no-pull) PULL=0; shift ;;
    --build) BUILD=1; shift ;;
    --no-cert-export) CERT_EXPORT=0; shift ;;
    --relax-strict-tls) RELAX=1; shift ;;
    --no-browser) BROWSER=0; shift ;;
    -h|--help) sed -n '7,18p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see: bash start.sh --help)" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '\n%s\n' "$1" >&2; exit 1; }
port_busy() {  # true if something is listening on 127.0.0.1:$1
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}
app_ready() { curl --noproxy '*' -fsS -m 2 "http://127.0.0.1:$1/healthz" >/dev/null 2>&1; }

# 1. Docker available and running?
step "Checking Docker"
command -v docker >/dev/null || fail "Docker was not found. Install Docker Desktop (https://www.docker.com/products/docker-desktop/) and try again."
if ! version="$(docker info --format '{{.ServerVersion}}' 2>/dev/null)"; then
  fail "Docker is installed but not running. Start Docker Desktop, wait until it says 'Engine running', then try again."
fi
echo "Docker engine $version is running."

# 2. Network CA certificates
step "Checking network certificates"
mkdir -p "$CERTS"
count_certs() { find "$CERTS" -maxdepth 1 -type f \( -name '*.pem' -o -name '*.crt' \) | wc -l | tr -d ' '; }
if [ "$(count_certs)" = 0 ] && [ "$CERT_EXPORT" = 1 ]; then
  echo "No certificates in $CERTS yet - checking whether your network inspects HTTPS..."
  if ! bash "$ROOT/scripts/export-network-root-ca.sh" --skip-if-public; then
    echo "Certificate export did not complete. The app will still start; if OpenAI verification" >&2
    echo "reports a TLS error, see README section "Corporate networks"." >&2
  fi
fi
if [ "$(count_certs)" != 0 ]; then
  echo "Using certificate file(s): $(cd "$CERTS" && ls -1 ./*.pem ./*.crt 2>/dev/null | sed 's#^\./##' | paste -sd ',' -)"
else
  echo "No extra certificates (not needed unless your network inspects HTTPS)."
fi

# 3. Image
if [ "$BUILD" = 1 ]; then
  IMAGE="project-quarry-demo:local"
  step "Building $IMAGE from this folder (the first build takes a few minutes)"
  docker build -t "$IMAGE" "$ROOT" || fail "The image could not be built. The build log is shown above."
elif [ "$PULL" = 1 ] && [[ "$IMAGE" == */* ]]; then
  step "Pulling $IMAGE"
  if ! pull_out="$(docker pull "$IMAGE" 2>&1)"; then
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
      echo "Could not pull the latest image; using the copy already on this computer."
    else
      echo "$pull_out" >&2
      fail "Could not pull $IMAGE and no local copy exists. If you have not published the image yet, build it here instead: bash start.sh --build"
    fi
  else
    echo "Image is up to date."
  fi
fi

# 4. Replace any existing container
step "Starting the container"
if [ -n "$(docker ps -a --filter "name=^/${NAME}\$" --format '{{.ID}}')" ]; then
  echo "Removing the previous $NAME container (saved settings are kept in the '$VOLUME' volume)."
  docker rm -f "$NAME" >/dev/null
  sleep 1
fi
if port_busy "$PORT"; then
  fail "Port $PORT on 127.0.0.1 is already in use by another program. Run again with a different port, for example: bash start.sh --port 5076"
fi

run_args=(run -d --name "$NAME" -p "127.0.0.1:${PORT}:5075" -v "${VOLUME}:/data" -v "${CERTS}:/certs:ro")
[ "$RELAX" = 1 ] && run_args+=(-e QUARRY_DEMO_TLS_RELAX_X509_STRICT=1)
run_args+=("$IMAGE")
docker "${run_args[@]}" >/dev/null || fail "The container could not be started."

# 5. Wait for the app
echo "Waiting for the app to start..."
ready=0
for _ in $(seq 1 40); do
  if app_ready "$PORT"; then ready=1; break; fi
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ] || break
  sleep 0.75
done
logs="$(docker logs "$NAME" 2>&1 || true)"
if [ "$ready" != 1 ]; then
  echo "$logs"
  fail "The app did not start. The container log is shown above."
fi
echo "$logs" | grep -E "extra CA certificate|Skipped .*certificate" | sed -E 's/^[^ ]+ [^ ]+ [^ ]+ [^ ]+: //' || true

URL="http://127.0.0.1:$PORT"
step "The Project Quarry demo is running at $URL"
echo "Scripted scenarios work straight away. Open Setup to add an OpenAI key for live mode."
echo "Stop it with: bash stop.sh   (or: docker stop $NAME)"
if [ "$BROWSER" = 1 ]; then
  if command -v open >/dev/null; then open "$URL"
  elif command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true
  fi
fi
