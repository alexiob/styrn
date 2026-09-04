#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct FakePodman {
    root: PathBuf,
    path: PathBuf,
    log: PathBuf,
}

impl FakePodman {
    fn new() -> Self {
        let unique = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "styrn-linux-cargo-harness-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create fake podman directory");
        let path = root.join("podman");
        let log = root.join("podman.log");
        fs::write(&path, FAKE_PODMAN).expect("write fake podman");
        let mut permissions = fs::metadata(&path)
            .expect("read fake podman metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("mark fake podman executable");
        Self { root, path, log }
    }

    fn run(&self, scenario: &str, args: &[&str], current_dir: &Path) -> Output {
        let parent = self.path.parent().expect("fake podman parent");
        let old_path = env::var_os("PATH").expect("PATH is set");
        let path = format!("{}:{}", parent.display(), old_path.to_string_lossy());
        Command::new(env!("CARGO_MANIFEST_DIR").to_owned() + "/scripts/test-linux-arm64-cargo.sh")
            .args(args)
            .current_dir(current_dir)
            .env("PATH", path)
            .env("PODMAN_LOG", &self.log)
            .env("PODMAN_SCENARIO", scenario)
            .output()
            .expect("run Linux cargo harness")
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for FakePodman {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn native_arm64_cargo_harness_enforces_and_exercises_its_contract() {
    // This fails if the wrapper is absent or stops running its actual Podman boundary.
    let fake = FakePodman::new();
    let attestation = fake.run("ok", &["target-attestation"], &env::temp_dir());
    assert!(
        attestation.status.success(),
        "attestation failed: {}; fake log: {}",
        stderr(&attestation),
        fake.log()
    );
    let attestation_stdout = String::from_utf8_lossy(&attestation.stdout);
    assert!(attestation_stdout.contains("podman_machine=styrn-linux"));
    assert!(attestation_stdout.contains("podman_host_arch=arm64"));
    assert!(attestation_stdout.contains("pinned_image=docker.io/library/rust:1.98-bookworm@sha256:56bfc6a715db852bdafd5e4bdf68ef7abceb791e77c47e5d87c7e861702a9ca6"));
    assert!(attestation_stdout.contains("image_platform=linux/arm64"));
    assert!(attestation_stdout.contains("container_uname=aarch64"));
    assert!(attestation_stdout.contains("rust_host=aarch64-unknown-linux-gnu"));
    assert!(attestation_stdout.contains("runner_uid_gid=1000:1000"));
    let log = fake.log();
    assert!(log.contains("--platform\nlinux/arm64"), "{log}");
    assert!(log.contains("--userns=keep-id:uid=1000,gid=1000"), "{log}");
    assert!(log.contains("--user\n1000:1000"), "{log}");
    assert!(log.contains("/workspace:ro"), "{log}");
    assert!(log.contains("styrn-cargo-registry-arm64"), "{log}");
    assert!(log.contains("styrn-cargo-target-arm64"), "{log}");

    let existing_volumes = FakePodman::new().run(
        "existing_volumes",
        &["target-attestation"],
        &env::temp_dir(),
    );
    assert!(
        existing_volumes.status.success(),
        "existing task-owned volumes must be reusable: {}",
        stderr(&existing_volumes)
    );

    let wrong_selected = FakePodman::new().run(
        "wrong_selected_machine",
        &["target-attestation"],
        &env::temp_dir(),
    );
    assert!(
        wrong_selected.status.success(),
        "an ambient non-styrn connection must not affect explicit selection: {}",
        stderr(&wrong_selected)
    );

    let wrong_host =
        FakePodman::new().run("wrong_host_arch", &["target-attestation"], &env::temp_dir());
    assert!(!wrong_host.status.success());
    assert!(stderr(&wrong_host).contains("Podman host architecture must be arm64"));

    let wrong_image = FakePodman::new().run(
        "wrong_image_arch",
        &["target-attestation"],
        &env::temp_dir(),
    );
    assert!(!wrong_image.status.success());
    assert!(stderr(&wrong_image).contains("pinned image platform must be linux/arm64"));

    let root_runner = FakePodman::new().run("root_uid", &["target-attestation"], &env::temp_dir());
    assert!(!root_runner.status.success());
    assert!(stderr(&root_runner).contains("runner identity must be non-root 1000:1000"));

    let zero_filter = FakePodman::new().run(
        "zero_filter",
        &["test-filter", "does_not_exist"],
        &env::temp_dir(),
    );
    assert!(!zero_filter.status.success());
    assert!(stderr(&zero_filter).contains("selected zero tests"));

    let pass_through_fake = FakePodman::new();
    let pass_through = pass_through_fake.run(
        "pass_through",
        &["cargo", "--", "test", "--locked", "--exact", "module::case"],
        &env::temp_dir(),
    );
    assert!(pass_through.status.success(), "{}", stderr(&pass_through));
    let pass_through_log = pass_through_fake.log();
    for expected in [
        "RUNNER_ARG:test",
        "RUNNER_ARG:--locked",
        "RUNNER_ARG:--exact",
        "RUNNER_ARG:module::case",
    ] {
        assert!(
            pass_through_log.contains(expected),
            "missing {expected} in {pass_through_log}"
        );
    }

    let child_failure = FakePodman::new().run(
        "child_exit_37",
        &["cargo", "--", "--version"],
        &env::temp_dir(),
    );
    assert_eq!(
        child_failure.status.code(),
        Some(37),
        "{}",
        stderr(&child_failure)
    );
}

const FAKE_PODMAN: &str = r#"#!/bin/sh
set -eu

: "${PODMAN_LOG:?}"
: "${PODMAN_SCENARIO:?}"
EXPECTED_IMAGE='docker.io/library/rust:1.98-bookworm@sha256:56bfc6a715db852bdafd5e4bdf68ef7abceb791e77c47e5d87c7e861702a9ca6'
printf 'CALL\n' >> "$PODMAN_LOG"
for argument in "$@"; do
    printf '%s\n' "$argument" >> "$PODMAN_LOG"
done

[ "${1-}" = --connection ] || exit 89
[ "${2-}" = styrn-linux ] || exit 89
printf 'SELECTED_CONNECTION:%s\n' "$2" >> "$PODMAN_LOG"
shift 2
if [ "$PODMAN_SCENARIO" = wrong_selected_machine ]; then
    printf '%s\n' 'AMBIENT_CONNECTION=other-arm64-machine' >> "$PODMAN_LOG"
fi

exact() {
    [ "$1" = "$2" ] || exit "$3"
}

runner_prefix() {
    exact "$1" --rm 99; shift
    exact "$1" --platform 99; shift
    exact "$1" linux/arm64 99; shift
    exact "$1" --userns=keep-id:uid=1000,gid=1000 99; shift
    exact "$1" --user 99; shift
    exact "$1" 1000:1000 99; shift
    exact "$1" --env 99; shift
    exact "$1" CARGO_HOME=/cargo 99; shift
    exact "$1" -v 99; shift
    case "$1" in *:/workspace:ro) ;; *) exit 99 ;; esac; shift
    exact "$1" -v 99; shift
    exact "$1" styrn-cargo-registry-arm64:/cargo 99; shift
    exact "$1" -v 99; shift
    exact "$1" styrn-cargo-target-arm64:/workspace/target 99; shift
    exact "$1" --workdir 99; shift
    exact "$1" /workspace 99; shift
    exact "$1" "$EXPECTED_IMAGE" 99; shift
    printf 'RUNNER_IMAGE:%s\n' "$EXPECTED_IMAGE" >> "$PODMAN_LOG"
    RUNNER_REMAINDER="$*"
}

initializer_prefix() {
    exact "$1" --rm 99; shift
    exact "$1" --platform 99; shift
    exact "$1" linux/arm64 99; shift
    exact "$1" --userns=keep-id:uid=1000,gid=1000 99; shift
    exact "$1" --user 99; shift
    exact "$1" 0:0 99; shift
    exact "$1" -v 99; shift
    exact "$1" styrn-cargo-registry-arm64:/cargo 99; shift
    exact "$1" -v 99; shift
    exact "$1" styrn-cargo-target-arm64:/workspace/target 99; shift
    exact "$1" "$EXPECTED_IMAGE" 99; shift
    exact "$1" sh 99; shift
    exact "$1" -ec 99; shift
    exact "$1" 'chown -R 1000:1000 /cargo /workspace/target' 99; shift
    [ "$#" -eq 0 ] || exit 99
}

case "${1-}:${2-}" in
    machine:inspect)
        [ "${3-}" = "styrn-linux" ] || exit 90
        printf '%s\n' 'styrn-linux'
        ;;
    info:--format)
        if [ "$PODMAN_SCENARIO" = wrong_host_arch ]; then printf '%s\n' amd64; else printf '%s\n' arm64; fi
        ;;
    pull:--platform)
        [ "${3-}" = linux/arm64 ] || exit 91
        [ "${4-}" = "$EXPECTED_IMAGE" ] || exit 99
        ;;
    image:inspect)
        [ "${3-}" = "$EXPECTED_IMAGE" ] || exit 99
        if [ "$PODMAN_SCENARIO" = wrong_image_arch ]; then printf '%s\n' linux/amd64; else printf '%s\n' linux/arm64; fi
        ;;
    volume:create)
        [ "$PODMAN_SCENARIO" != existing_volumes ] || exit 97
        case "${3-}" in styrn-cargo-registry-arm64|styrn-cargo-target-arm64) printf '%s\n' "$3" ;; *) exit 92 ;; esac
        ;;
    volume:inspect)
        [ "$PODMAN_SCENARIO" = existing_volumes ] || exit 98
        case "${3-}" in styrn-cargo-registry-arm64|styrn-cargo-target-arm64) : ;; *) exit 92 ;; esac
        ;;
    run:*)
        arguments=" $* "
        shift
        case "$arguments" in *' --privileged '*|*' --network host '*|*'/podman.sock'*) exit 93 ;; esac
        case "$arguments" in
            *' --user 0:0 '*)
                initializer_prefix "$@"
                ;;
            *)
                runner_prefix "$@"
                for argument in "$@"; do printf 'RUNNER_ARG:%s\n' "$argument" >> "$PODMAN_LOG"; done
                case "$arguments" in
                    *' cargo '*)
                        if [ "$PODMAN_SCENARIO" = pass_through ]; then
                            exact "$RUNNER_REMAINDER" 'cargo test --locked --exact module::case' 99
                        fi
                        if [ "$PODMAN_SCENARIO" = zero_filter ] && printf '%s\n' "$arguments" | grep -q -- ' --list '; then
                            printf '%s\n' '0 tests, 0 benchmarks'
                        elif [ "$PODMAN_SCENARIO" = child_exit_37 ]; then
                            exit 37
                        else
                            printf '%s\n' 'module::case: test'
                        fi
                        ;;
                    *)
                        if [ "$PODMAN_SCENARIO" = root_uid ]; then runner_uid=0; else runner_uid=1000; fi
                        printf 'container_uname=aarch64\nrust_host=aarch64-unknown-linux-gnu\nrunner_uid=%s\nrunner_gid=1000\n' "$runner_uid"
                        ;;
                esac
                ;;
        esac
        ;;
    *) exit 96 ;;
esac
"#;
