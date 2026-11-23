#!/usr/bin/env bash
# Runs the tiberius tests against a disposable SQL Server container built from
# docker/, the same images CI uses. Needs only docker, not docker compose.
#
#   scripts/docker-test.sh run  [cargo test args]  start, test, then remove the container
#   scripts/docker-test.sh up                      start it (or reuse it) and wait until it accepts logins
#   scripts/docker-test.sh test [cargo test args]  test against the running container
#   scripts/docker-test.sh env                     print the TIBERIUS_TEST_CONNECTION_STRING export
#   scripts/docker-test.sh down                    remove the container
#
# With no cargo arguments, `cargo test --no-fail-fast` runs. Unless the
# arguments already contain `--`, `-- --include-ignored` is appended, so the
# live tests in tests/rpc_helpers_live.rs run as well.
#
# Environment:
#   TIBERIUS_TEST_SERVER  2025 | 2022 | 2019 | 2017 | azure-sql-edge   (default 2022)
#   TIBERIUS_TEST_PORT    host port for `up` and `run`, bound to 127.0.0.1 (default 1434)

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER=${TIBERIUS_TEST_SERVER:-2022}
PORT=${TIBERIUS_TEST_PORT:-1434}
# Matches docker-compose.yml and tests/custom-cert.rs.
SA_PASSWORD='<YourStrong@Passw0rd>'

case "$SERVER" in
  azure-sql-edge) DOCKERFILE=docker-azure-sql-edge.dockerfile ;;
  *) DOCKERFILE=docker-mssql-$SERVER.dockerfile ;;
esac
if [[ ! -f "$ROOT/docker/$DOCKERFILE" ]]; then
  echo "unknown TIBERIUS_TEST_SERVER '$SERVER': no docker/$DOCKERFILE" >&2
  exit 2
fi

NAME=tiberius-test-mssql-$SERVER
STARTED=0

is_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" == true ]]
}

# The host port of the running container, whatever TIBERIUS_TEST_PORT says now.
running_port() {
  is_running || return 1
  docker port "$NAME" 1433/tcp | head -n1 | sed 's/.*://'
}

connection_string() {
  echo "server=tcp:localhost,$1;user=SA;password=$SA_PASSWORD;TrustServerCertificate=true"
}

check_cert() {
  if ! openssl x509 -checkend 0 -noout -in "$ROOT/docker/certs/server.crt" >/dev/null; then
    echo "docker/certs/server.crt has expired, so tests/custom-cert.rs would fail. Reissue it with:" >&2
    echo "  (cd docker/certs && ./generate-signed-cert.sh server)" >&2
    exit 1
  fi
}

sqlcmd_ready() {
  local sqlcmd=$1
  case "$sqlcmd" in
    "") docker logs "$NAME" 2>&1 | grep -q 'SQL Server is now ready for client connections' ;;
    *18*) docker exec "$NAME" "$sqlcmd" -S localhost -U sa -P "$SA_PASSWORD" -C -l 2 -b -Q 'SELECT 1' >/dev/null 2>&1 ;;
    *) docker exec "$NAME" "$sqlcmd" -S localhost -U sa -P "$SA_PASSWORD" -l 2 -b -Q 'SELECT 1' >/dev/null 2>&1 ;;
  esac
}

wait_ready() {
  local deadline=$((SECONDS + 180)) sqlcmd="" candidate
  # Azure SQL Edge ships no sqlcmd; fall back to its startup log line.
  for candidate in /opt/mssql-tools18/bin/sqlcmd /opt/mssql-tools/bin/sqlcmd; do
    if docker exec "$NAME" test -x "$candidate" 2>/dev/null; then
      sqlcmd=$candidate
      break
    fi
  done

  printf 'waiting for %s on 127.0.0.1:%s ' "$NAME" "$(running_port)"
  until sqlcmd_ready "$sqlcmd"; do
    if ! is_running || ((SECONDS >= deadline)); then
      echo
      docker logs --tail 30 "$NAME" >&2 || true
      echo "$NAME did not become ready" >&2
      exit 1
    fi
    printf .
    sleep 2
  done
  echo ' ready'
}

up() {
  check_cert
  if is_running; then
    echo "$NAME is already running on 127.0.0.1:$(running_port)"
  else
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker build -t "$NAME:latest" -f "$ROOT/docker/$DOCKERFILE" "$ROOT/docker"
    docker run -d --name "$NAME" \
      -e ACCEPT_EULA=Y \
      -e MSSQL_SA_PASSWORD="$SA_PASSWORD" \
      -e SA_PASSWORD="$SA_PASSWORD" \
      -p "127.0.0.1:$PORT:1433" \
      "$NAME:latest" >/dev/null
    STARTED=1
  fi
  wait_ready
}

run_tests() {
  local port has_separator=0 arg
  if ! port=$(running_port); then
    echo "$NAME is not running; start it with: $0 up" >&2
    exit 1
  fi
  (($# > 0)) || set -- --no-fail-fast
  for arg in "$@"; do
    [[ "$arg" == -- ]] && has_separator=1
  done
  ((has_separator)) || set -- "$@" -- --include-ignored

  export TIBERIUS_TEST_CONNECTION_STRING
  TIBERIUS_TEST_CONNECTION_STRING=$(connection_string "$port")
  cd "$ROOT"
  echo "+ cargo test $*"
  cargo test "$@"
}

down() {
  docker rm -f "$NAME" >/dev/null 2>&1 && echo "removed $NAME" || true
}

command=${1:-}
shift || true
case "$command" in
  up) up ;;
  test) run_tests "$@" ;;
  down) down ;;
  env)
    port=$(running_port) || port=$PORT
    printf "export TIBERIUS_TEST_CONNECTION_STRING='%s'\n" "$(connection_string "$port")"
    ;;
  run)
    up
    # Leave a container that was already running for whoever started it.
    if ((STARTED)); then trap down EXIT; fi
    run_tests "$@"
    ;;
  *)
    sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    [[ -z "$command" || "$command" == help || "$command" == -h || "$command" == --help ]] || exit 2
    ;;
esac
