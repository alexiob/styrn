#![allow(dead_code)]

#[path = "../src/cli/mod.rs"]
mod cli;
#[path = "../src/manifest/mod.rs"]
mod manifest;
#[path = "../src/output/mod.rs"]
mod output;
#[path = "../src/platform/mod.rs"]
mod platform;
#[path = "../src/resources/mod.rs"]
mod resources;
#[path = "../src/rpc/mod.rs"]
mod rpc;
#[path = "../src/setup/mod.rs"]
mod setup;
#[path = "../src/transport/mod.rs"]
mod transport;

use output::ErrorCode;
use std::path::{Path, PathBuf};
use transport::{
    ssh_arguments, ssh_keyscan_arguments, verify_scanned_host_key, PinnedHostKey, RpcTarget,
    SshTransport, TransportErrorKind,
};

const ED25519_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const ED25519_FINGERPRINT: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";

#[test]
fn host_key_scan_is_bounded_canonical_and_unambiguous() {
    let scan = format!("worker.example ssh-ed25519 {ED25519_KEY}\n");
    let selected = PinnedHostKey::select_scan(scan.as_bytes(), None).unwrap();
    assert_eq!(selected.algorithm(), "ssh-ed25519");
    assert_eq!(selected.base64(), ED25519_KEY);
    assert_eq!(selected.fingerprint(), ED25519_FINGERPRINT);

    let duplicate = format!("{scan}[worker.example]:22 ssh-ed25519 {ED25519_KEY}\n");
    assert_eq!(
        PinnedHostKey::select_scan(duplicate.as_bytes(), None).unwrap(),
        selected
    );

    let other = "AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA";
    for hostile in [
        b"worker.example ssh-ed25519 not-base64\n".to_vec(),
        format!("{scan}worker.example ssh-ed25519 {other}\n").into_bytes(),
        vec![b'x'; 1024 * 1024 + 1],
    ] {
        let error = PinnedHostKey::select_scan(&hostile, None).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::Authentication);
        assert!(!error.to_string().contains("not-base64"));
    }

    let selected = PinnedHostKey::select_scan(scan.as_bytes(), Some(ED25519_FINGERPRINT)).unwrap();
    assert_eq!(selected.fingerprint(), ED25519_FINGERPRINT);
    let error = PinnedHostKey::select_scan(
        scan.as_bytes(),
        Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), TransportErrorKind::Authentication);
}

#[test]
fn host_key_tool_argv_is_exact_and_option_safe() {
    assert_eq!(
        ssh_keyscan_arguments("worker.example", 22).unwrap(),
        [
            "-T",
            "10",
            "-p",
            "22",
            "-t",
            "ed25519,ecdsa,rsa",
            "--",
            "worker.example",
        ]
    );

    for hostile in [
        "-oProxyCommand=touch /tmp/pwned",
        "user@worker",
        "worker example",
        "worker/example",
        "[2001:db8::1",
        "worker\nexample",
    ] {
        assert!(ssh_keyscan_arguments(hostile, 22).is_err(), "{hostile:?}");
    }
    assert!(ssh_keyscan_arguments("[2001:db8::1]", 22).is_ok());
}

#[test]
fn ssh_transport_argv_has_one_fixed_remote_command_and_no_interpolation() {
    let pin = PinnedHostKey::select_scan(
        format!("worker.example ssh-ed25519 {ED25519_KEY}\n").as_bytes(),
        Some(ED25519_FINGERPRINT),
    )
    .unwrap();
    let target = RpcTarget::new(
        "worker.example",
        "alex",
        22,
        PathBuf::from("/controller keys/id with spaces"),
        pin,
    )
    .unwrap();
    let argv = ssh_arguments(&target, Path::new("/state/known hosts")).unwrap();
    assert_eq!(
        argv,
        [
            "-T",
            "-oBatchMode=yes",
            "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=/state/known hosts",
            "-oGlobalKnownHostsFile=none",
            "-oCheckHostIP=no",
            "-oConnectTimeout=10",
            "-oConnectionAttempts=1",
            "-i",
            "/controller keys/id with spaces",
            "-p",
            "22",
            "--",
            "alex@worker.example",
            "styrn rpc serve --stdio",
        ]
    );
    assert_eq!(argv.last().unwrap(), "styrn rpc serve --stdio");
    assert_eq!(
        argv.iter()
            .filter(|item| item.contains("worker.example"))
            .count(),
        1
    );

    for (host, user) in [
        ("worker.example", "-root"),
        ("worker.example", "other@user"),
        ("worker.example", "user/name"),
        ("worker;touch-pwned", "alex"),
    ] {
        assert!(RpcTarget::new(
            host,
            user,
            22,
            PathBuf::from("/id"),
            target.host_key().clone()
        )
        .is_err());
    }
}

#[test]
fn ssh_transport_missing_tool_and_changed_key_are_typed_before_spawn() {
    let pin = PinnedHostKey::select_scan(
        format!("worker.example ssh-ed25519 {ED25519_KEY}\n").as_bytes(),
        None,
    )
    .unwrap();
    let target = RpcTarget::new("worker.example", "alex", 22, PathBuf::from("/id"), pin).unwrap();
    let transport = SshTransport::new(
        PathBuf::from("definitely-missing-ssh"),
        PathBuf::from("definitely-missing-keyscan"),
        PathBuf::from("/known_hosts"),
    );
    let error = transport.verify_host_key(&target).unwrap_err();
    assert_eq!(error.kind(), TransportErrorKind::CapabilityUnavailable);
    assert_eq!(error.code(), ErrorCode::CapabilityUnsatisfied);
    assert!(!error.to_string().contains("definitely-missing"));

    let changed =
        "worker.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA\n";
    let error = verify_scanned_host_key(&target, changed.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), TransportErrorKind::Authentication);
    assert_eq!(error.code(), ErrorCode::TransportAuthFailed);
}

#[test]
fn transport_error_categories_do_not_collapse() {
    assert_eq!(
        TransportErrorKind::CapabilityUnavailable.code(),
        ErrorCode::CapabilityUnsatisfied
    );
    assert_eq!(
        TransportErrorKind::Unreachable.code(),
        ErrorCode::TransportUnreachable
    );
    assert_eq!(
        TransportErrorKind::Authentication.code(),
        ErrorCode::TransportAuthFailed
    );
    assert_ne!(
        TransportErrorKind::Authentication.code(),
        ErrorCode::TransportSessionLost
    );
    assert_ne!(
        TransportErrorKind::Authentication.code(),
        ErrorCode::ProtocolMalformed
    );
    assert_ne!(
        TransportErrorKind::Authentication.code(),
        ErrorCode::RemoteExecutionFailed
    );
}
