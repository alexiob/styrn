#!/bin/sh
# Developer test infrastructure only. This never runs as part of the Styrn CLI.
set -eu

IMAGE='docker.io/library/rust:1.98-bookworm@sha256:56bfc6a715db852bdafd5e4bdf68ef7abceb791e77c47e5d87c7e861702a9ca6'
MACHINE='styrn-linux'
REGISTRY_VOLUME='styrn-cargo-registry-arm64'
TARGET_VOLUME='styrn-cargo-target-arm64'

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

usage() {
    printf '%s\n' 'usage: scripts/test-linux-arm64-cargo.sh target-attestation | cargo -- <args> | test-filter <substring>' >&2
}

fail() {
    printf '%s\n' "error: $*" >&2
    exit 2
}

require_exact() {
    actual=$1
    expected=$2
    description=$3
    [ "$actual" = "$expected" ] || fail "$description must be $expected (got $actual)"
}

podman_styrn() {
    podman --connection "$MACHINE" "$@"
}

runner() {
    podman_styrn run --rm \
        --platform linux/arm64 \
        --userns=keep-id:uid=1000,gid=1000 \
        --user 1000:1000 \
        --env CARGO_HOME=/cargo \
        -v "$REPOSITORY_ROOT:/workspace:ro" \
        -v "$REGISTRY_VOLUME:/cargo" \
        -v "$TARGET_VOLUME:/workspace/target" \
        --workdir /workspace \
        "$IMAGE" "$@"
}

ensure_task_volume() {
    if podman_styrn volume inspect "$1" >/dev/null 2>&1; then
        return
    fi
    podman_styrn volume create "$1" >/dev/null
}

preflight() {
    machine=$(podman_styrn machine inspect "$MACHINE" --format '{{.Name}}')
    require_exact "$machine" "$MACHINE" 'selected Podman machine'

    host_arch=$(podman_styrn info --format '{{.Host.Arch}}')
    require_exact "$host_arch" arm64 'Podman host architecture'

    podman_styrn pull --platform linux/arm64 "$IMAGE" >/dev/null
    image_platform=$(podman_styrn image inspect "$IMAGE" --format '{{.Os}}/{{.Architecture}}')
    require_exact "$image_platform" linux/arm64 'pinned image platform'

    ensure_task_volume "$REGISTRY_VOLUME"
    ensure_task_volume "$TARGET_VOLUME"
    podman_styrn run --rm \
        --platform linux/arm64 \
        --userns=keep-id:uid=1000,gid=1000 \
        --user 0:0 \
        -v "$REGISTRY_VOLUME:/cargo" \
        -v "$TARGET_VOLUME:/workspace/target" \
        "$IMAGE" sh -ec 'chown -R 1000:1000 /cargo /workspace/target' >/dev/null
}

attest() {
    facts=$(runner sh -ec '
        printf "container_uname="; uname -m
        rustc -vV | sed -n "s/^host: /rust_host=/p"
        printf "runner_uid="; id -u
        printf "runner_gid="; id -g
    ')
    container_uname=$(printf '%s\n' "$facts" | sed -n 's/^container_uname=//p')
    rust_host=$(printf '%s\n' "$facts" | sed -n 's/^rust_host=//p')
    runner_uid=$(printf '%s\n' "$facts" | sed -n 's/^runner_uid=//p')
    runner_gid=$(printf '%s\n' "$facts" | sed -n 's/^runner_gid=//p')

    require_exact "$container_uname" aarch64 'container uname -m'
    require_exact "$rust_host" aarch64-unknown-linux-gnu 'rustc host'
    [ "$runner_uid" != 0 ] && [ "$runner_uid" = 1000 ] && [ "$runner_gid" = 1000 ] \
        || fail "runner identity must be non-root 1000:1000 (got $runner_uid:$runner_gid)"

    printf 'podman_machine=%s\n' "$machine"
    printf 'podman_host_arch=%s\n' "$host_arch"
    printf 'pinned_image=%s\n' "$IMAGE"
    printf 'image_platform=%s\n' "$image_platform"
    printf 'container_uname=%s\n' "$container_uname"
    printf 'rust_host=%s\n' "$rust_host"
    printf 'runner_uid_gid=%s:%s\n' "$runner_uid" "$runner_gid"
}

run_filter() {
    filter=$1
    tmp_output=$(mktemp "${TMPDIR:-/tmp}/styrn-linux-arm64-cargo.XXXXXX")
    cleanup_filter() {
        rm -f "$tmp_output"
    }
    trap cleanup_filter EXIT HUP INT TERM

    if runner cargo test --locked "$filter" -- --list >"$tmp_output"; then
        :
    else
        status=$?
        cat "$tmp_output"
        exit "$status"
    fi
    cat "$tmp_output"
    if ! grep -F -- "$filter" "$tmp_output" | grep -Eq ': test$'; then
        fail "test-filter selected zero tests for substring: $filter"
    fi
    runner cargo test --locked "$filter"
}

[ "$#" -gt 0 ] || { usage; exit 2; }

case "$1" in
    target-attestation)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        attest
        ;;
    cargo)
        [ "$#" -ge 3 ] && [ "$2" = '--' ] || { usage; exit 2; }
        shift 2
        preflight
        attest >/dev/null
        runner cargo "$@"
        ;;
    test-filter)
        [ "$#" -eq 2 ] && [ -n "$2" ] || { usage; exit 2; }
        preflight
        attest >/dev/null
        run_filter "$2"
        ;;
    *)
        usage
        exit 2
        ;;
esac
