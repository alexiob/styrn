#[path = "../src/platform/mod.rs"]
mod platform;

#[path = "../src/manifest/mod.rs"]
mod manifest;

use jsonschema::Validator;
use manifest::{MachineManifest, MachineManifestStore};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Barrier};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn current_worker_principal() -> platform::WorkerPrincipal {
    platform::resolve_current_worker_principal()
        .expect("manifest contract tests require a real non-privileged caller")
}

fn current_user_manifest() -> MachineManifest {
    let principal = current_worker_principal();
    let layout = platform::resolve_worker_directory_layout(
        platform::InstallationScope::User,
        &principal,
        None,
    )
    .unwrap();
    let mut manifest = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    {
        manifest.platform.os = manifest::OperatingSystem::Linux;
    }
    #[cfg(target_os = "windows")]
    {
        manifest.platform.os = manifest::OperatingSystem::Windows;
    }
    let identity = manifest.worker_identity.as_mut().unwrap();
    identity.principal_kind = principal.principal_kind();
    identity.principal_id = principal.principal_id().to_owned();
    identity.name = principal.name().to_owned();
    manifest.transport.as_mut().unwrap().user = Some(principal.name().to_owned());
    manifest.paths.root = layout.root().to_str().unwrap().to_owned();
    manifest.paths.repos = layout.repos().to_str().unwrap().to_owned();
    manifest.paths.jobs = layout.jobs().to_str().unwrap().to_owned();
    manifest.paths.cache = layout.cache().to_str().unwrap().to_owned();
    manifest.paths.artifacts = layout.artifacts().to_str().unwrap().to_owned();
    manifest.paths.logs = layout.logs().to_str().unwrap().to_owned();
    manifest.validate().unwrap();
    manifest
}

#[cfg(unix)]
fn system_manifest_for(principal: &platform::WorkerPrincipal) -> MachineManifest {
    let mut manifest = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap();
    manifest.installation.as_mut().unwrap().scope = platform::InstallationScope::System;
    let identity = manifest.worker_identity.as_mut().unwrap();
    identity.mode = manifest::WorkerIdentityMode::Dedicated;
    identity.principal_kind = principal.principal_kind();
    identity.principal_id = principal.principal_id().to_owned();
    identity.name = principal.name().to_owned();
    identity.isolation = platform::WorkerIsolation::DedicatedAccount;
    manifest.transport.as_mut().unwrap().user = Some(principal.name().to_owned());
    #[cfg(target_os = "linux")]
    {
        manifest.platform.os = manifest::OperatingSystem::Linux;
        set_manifest_paths_root(&mut manifest, "/srv/styrn", '/');
    }
    #[cfg(target_os = "macos")]
    {
        set_manifest_paths_root(&mut manifest, "/Users/Shared/Styrn", '/');
    }
    manifest.validate().unwrap();
    manifest
}

fn schema_validator() -> Validator {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/machine-v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn assert_schema_valid(value: &Value) {
    let validator = schema_validator();
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        panic!(
            "machine JSON must validate against the checked-in schema:\n{}",
            errors.join("\n")
        );
    }
}

fn assert_schema_invalid(value: &Value) {
    assert!(
        !schema_validator().is_valid(value),
        "machine JSON unexpectedly validated against the checked-in schema"
    );
}

#[test]
fn checked_in_examples_parse_validate_and_round_trip_without_losing_fields() {
    for example in [
        "examples/machine.toml",
        "examples/machine.controller-worker.toml",
    ] {
        let input = fs::read_to_string(example).unwrap();
        let manifest = MachineManifest::parse_toml(&input).unwrap();
        manifest.validate().unwrap();
        let json = manifest.to_json_value().unwrap();
        assert_schema_valid(&json);

        let reparsed = MachineManifest::parse_toml(&manifest.to_toml().unwrap()).unwrap();
        assert_eq!(reparsed.to_json_value().unwrap(), json, "{example}");
    }
}

#[test]
fn current_user_worker_manifest_candidate_is_atomic_idempotent_and_preserves_operator_fields() {
    let principal = current_worker_principal();
    let base = stale_current_user_worker_draft();
    let base_before = draft_snapshot(&base);
    let layout = platform::resolve_worker_directory_layout(
        platform::InstallationScope::User,
        &principal,
        None,
    )
    .unwrap();

    let candidate =
        manifest::CurrentUserWorkerManifestCandidate::derive(&base, &principal).unwrap();
    let mut expected = base_before.clone();
    expected["worker_identity"] = serde_json::json!({
        "mode": "current-user",
        "principal_kind": principal.principal_kind(),
        "principal_id": principal.principal_id(),
        "name": principal.name(),
        "isolation": "shared-user",
    });
    expected["transport"]["user"] = Value::String(principal.name().to_owned());
    expected["paths"] = serde_json::json!({
        "root": layout.root().to_str().unwrap(),
        "repos": layout.repos().to_str().unwrap(),
        "jobs": layout.jobs().to_str().unwrap(),
        "cache": layout.cache().to_str().unwrap(),
        "artifacts": layout.artifacts().to_str().unwrap(),
        "logs": layout.logs().to_str().unwrap(),
    });

    assert_eq!(draft_snapshot(candidate.draft()), expected);
    assert_eq!(draft_snapshot(&base), base_before);
    assert_eq!(
        candidate.security_caveat(),
        "Current-user mode provides no OS-account isolation, no controller-credential isolation, and no same-user Styrn-state integrity boundary."
    );
    let repeated =
        manifest::CurrentUserWorkerManifestCandidate::derive(candidate.draft(), &principal)
            .unwrap();
    assert_eq!(draft_snapshot(repeated.draft()), expected);
    assert_eq!(draft_snapshot(&repeated.into_draft()), expected);

    let mut system = base.clone();
    system.installation.as_mut().unwrap().scope = platform::InstallationScope::System;
    assert_candidate_rejected_unchanged(
        &system,
        &principal,
        "current-user worker manifest projection requires a user-scope worker draft",
    );

    let mut controller_only = base.clone();
    controller_only.roles = vec![manifest::MachineRole::Controller];
    assert_candidate_rejected_unchanged(
        &controller_only,
        &principal,
        "current-user worker manifest projection requires a user-scope worker draft",
    );

    let mut missing_transport = base.clone();
    missing_transport.transport = None;
    assert_candidate_rejected_unchanged(
        &missing_transport,
        &principal,
        "current-user worker manifest projection requires an existing transport",
    );

    let mut nonnative = base;
    nonnative.platform.os = match native_operating_system_for_test() {
        manifest::OperatingSystem::Linux => manifest::OperatingSystem::Macos,
        manifest::OperatingSystem::Macos | manifest::OperatingSystem::Windows => {
            manifest::OperatingSystem::Linux
        }
    };
    assert_candidate_rejected_unchanged(
        &nonnative,
        &principal,
        "current-user worker manifest projection requires the native host platform",
    );
}

#[test]
fn current_user_worker_manifest_candidate_uses_the_exact_native_layout() {
    let principal = current_worker_principal();
    let candidate = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &principal,
    )
    .unwrap();
    let layout = platform::resolve_worker_directory_layout(
        platform::InstallationScope::User,
        &principal,
        None,
    )
    .unwrap();
    let projected_paths = [
        candidate.draft().paths.root.as_str(),
        candidate.draft().paths.repos.as_str(),
        candidate.draft().paths.jobs.as_str(),
        candidate.draft().paths.cache.as_str(),
        candidate.draft().paths.artifacts.as_str(),
        candidate.draft().paths.logs.as_str(),
    ];
    let exact_paths = [
        layout.root(),
        layout.repos(),
        layout.jobs(),
        layout.cache(),
        layout.artifacts(),
        layout.logs(),
    ];
    for (actual, exact) in projected_paths.into_iter().zip(exact_paths) {
        assert_eq!(Some(actual), exact.to_str());
    }
    for node in layout.materialization_nodes() {
        if matches!(node, platform::WorkerDirectoryNode::Support { .. }) {
            assert!(exact_paths
                .iter()
                .all(|path| *path != layout.path_for_node(node).unwrap()));
        }
    }

    let temp = TestDir::new();
    let exact_test_root = temp.path().join("explicit-worker-layout");
    let exact_test_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        principal.clone(),
        exact_test_root.clone(),
        None,
    );
    let exact_test_candidate =
        manifest::CurrentUserWorkerManifestCandidate::derive_with_layout_for_test(
            candidate.draft(),
            &principal,
            &exact_test_layout,
        )
        .unwrap();
    assert_eq!(
        exact_test_candidate.draft().paths.root,
        exact_test_root.to_str().unwrap()
    );

    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let store = MachineManifestStore::new_user(&path, principal.clone()).unwrap();
    let minted_id = store.write_generated(candidate.draft()).unwrap();
    assert_eq!(minted_id.get_version_num(), 7);
    let minted = store.read().unwrap().manifest;
    minted.validate().unwrap();
    assert_schema_valid(&minted.to_json_value().unwrap());

    let fixed_id = Uuid::parse_str("01991f5d-d72f-7b5e-a43d-9fcb61bd3267").unwrap();
    let seeded = fs::read_to_string(&path).unwrap().replacen(
        &minted_id.to_string(),
        &fixed_id.to_string(),
        1,
    );
    fs::write(&path, seeded).unwrap();
    assert_eq!(store.read().unwrap().manifest.machine_id, fixed_id);
    assert_eq!(store.write_generated(candidate.draft()).unwrap(), fixed_id);
    let first_bytes = fs::read(&path).unwrap();
    let first = store.read().unwrap().manifest;
    let first_json = first.to_json_value().unwrap();
    assert_schema_valid(&first_json);
    assert_eq!(first.machine_id, fixed_id);
    assert_eq!(
        first.worker_security_caveat(),
        Some(candidate.security_caveat())
    );
    assert!(!String::from_utf8(first_bytes.clone())
        .unwrap()
        .contains(candidate.security_caveat()));
    assert!(!first_json.to_string().contains(candidate.security_caveat()));

    let repeated =
        manifest::CurrentUserWorkerManifestCandidate::derive(candidate.draft(), &principal)
            .unwrap();
    assert_eq!(store.write_generated(repeated.draft()).unwrap(), fixed_id);
    assert_eq!(fs::read(&path).unwrap(), first_bytes);
    let second_json = store.read().unwrap().manifest.to_json_value().unwrap();
    assert_eq!(second_json, first_json);
}

#[test]
fn worker_manifest_requires_installation_and_worker_identity() {
    let input = fs::read_to_string("examples/machine.toml")
        .unwrap()
        .replace("[installation]\nscope = \"system\"\n\n", "")
        .replace(
            "[worker_identity]\nmode = \"dedicated\"\nprincipal_kind = \"windows-sid\"\nprincipal_id = \"S-1-5-21-111111111-222222222-333333333-1001\"\nname = \"build-agent\"\nisolation = \"dedicated-account\"\n\n",
            "",
        );

    let error = MachineManifest::parse_toml(&input)
        .expect_err("worker manifests without scope and identity must be rejected");

    assert_eq!(
        error.to_string(),
        "invalid machine manifest: installation is required"
    );
}

#[test]
fn worker_identity_contract_rejects_missing_transport_user_kind_id_and_policy_mismatches() {
    let unix = fs::read_to_string("examples/machine.controller-worker.toml").unwrap();
    let cases = [
        remove_toml_table(&unix, "worker_identity"),
        remove_line(&unix, "user ="),
        unix.replacen("principal_id = \"501\"", "principal_id = \"0501\"", 1),
        unix.replacen(
            "principal_kind = \"unix-uid\"",
            "principal_kind = \"windows-sid\"",
            1,
        ),
        unix.replacen(
            "isolation = \"shared-user\"",
            "isolation = \"dedicated-account\"",
            1,
        ),
        unix.replacen("mode = \"current-user\"", "mode = \"dedicated\"", 1),
        unix.replacen("user = \"alex-dev\"", "user = \"somebody-else\"", 1),
        unix.replacen("scope = \"user\"", "scope = \"unknown\"", 1),
        unix.replacen(
            "mode = \"current-user\"",
            "mode = \"current-user\"\nunexpected = true",
            1,
        ),
    ];
    for input in cases {
        assert!(MachineManifest::parse_toml(&input).is_err(), "{input}");
    }

    let valid = MachineManifest::parse_toml(&unix)
        .unwrap()
        .to_json_value()
        .unwrap();
    let mut missing_user = valid.clone();
    missing_user["transport"]
        .as_object_mut()
        .unwrap()
        .remove("user");
    assert_schema_invalid(&missing_user);
    let mut wrong_kind = valid.clone();
    wrong_kind["worker_identity"]["principal_kind"] = Value::String("windows-sid".to_owned());
    assert_schema_invalid(&wrong_kind);
    let mut wrong_id = valid.clone();
    wrong_id["worker_identity"]["principal_id"] = Value::String("S-1-5-21-1".to_owned());
    assert_schema_invalid(&wrong_id);

    for invalid_name in [" leading", "trailing "] {
        let mut value = valid.clone();
        value["worker_identity"]["name"] = Value::String(invalid_name.to_owned());
        value["transport"]["user"] = Value::String(invalid_name.to_owned());
        assert_schema_invalid(&value);
    }
    let mut maximum_uid = valid.clone();
    maximum_uid["worker_identity"]["principal_id"] = Value::String(u32::MAX.to_string());
    assert_schema_valid(&maximum_uid);
    let mut oversized_uid = valid.clone();
    oversized_uid["worker_identity"]["principal_id"] =
        Value::String((u64::from(u32::MAX) + 1).to_string());
    assert_schema_invalid(&oversized_uid);

    let mut windows = valid;
    windows["platform"]["os"] = Value::String("windows".to_owned());
    windows["worker_identity"]["principal_kind"] = Value::String("windows-sid".to_owned());
    windows["worker_identity"]["principal_id"] =
        Value::String("S-1-281474976710655-4294967295".to_owned());
    set_json_paths_root(&mut windows, r"C:\Users\alex-dev\AppData\Local\Styrn", '\\');
    assert_schema_valid(&windows);
    for invalid_sid in ["S-1-281474976710656-1", "S-1-5-4294967296"] {
        let mut value = windows.clone();
        value["worker_identity"]["principal_id"] = Value::String(invalid_sid.to_owned());
        assert_schema_invalid(&value);
    }
}

#[test]
fn manifest_paths_are_platform_native_scope_bound_and_root_relative() {
    let mac = fs::read_to_string("examples/machine.controller-worker.toml").unwrap();

    let linux_with_macos_paths = mac.replace("os = \"macos\"", "os = \"linux\"");
    assert!(MachineManifest::parse_toml(&linux_with_macos_paths).is_err());

    let user_with_system_root = mac.replace(
        "/Users/alex-dev/Library/Application Support/Styrn",
        "/Users/Shared/Styrn",
    );
    assert!(MachineManifest::parse_toml(&user_with_system_root).is_err());
    let user_with_nested_system_root = mac.replace(
        "/Users/alex-dev/Library/Application Support/Styrn",
        "/Users/Shared/Styrn/nested",
    );
    assert!(MachineManifest::parse_toml(&user_with_nested_system_root).is_err());

    let child_outside_root = mac.replacen(
        "jobs = \"/Users/alex-dev/Library/Application Support/Styrn/jobs\"",
        "jobs = \"/tmp/unrelated-jobs\"",
        1,
    );
    assert!(MachineManifest::parse_toml(&child_outside_root).is_err());

    let traversal = mac.replace(
        "root = \"/Users/alex-dev/Library/Application Support/Styrn\"",
        "root = \"/Users/alex-dev/Library/../Application Support/Styrn\"",
    );
    assert!(MachineManifest::parse_toml(&traversal).is_err());

    let valid_json = MachineManifest::parse_toml(&mac)
        .unwrap()
        .to_json_value()
        .unwrap();
    let mut schema_platform_mismatch = valid_json.clone();
    schema_platform_mismatch["platform"]["os"] = Value::String("windows".to_owned());
    schema_platform_mismatch["worker_identity"]["principal_kind"] =
        Value::String("windows-sid".to_owned());
    schema_platform_mismatch["worker_identity"]["principal_id"] =
        Value::String("S-1-5-21-1-2-3-1001".to_owned());
    assert_schema_invalid(&schema_platform_mismatch);

    let mut schema_traversal = valid_json.clone();
    set_json_paths_root(&mut schema_traversal, "/Users/alex-dev/../Styrn", '/');
    assert_schema_invalid(&schema_traversal);

    let mut schema_trailing_separator = valid_json.clone();
    schema_trailing_separator["paths"]["root"] = Value::String("/tmp/styrn/".to_owned());
    assert_schema_invalid(&schema_trailing_separator);

    let mut schema_detached_jobs = valid_json.clone();
    schema_detached_jobs["paths"]["jobs"] = Value::String("/tmp/unrelated-jobs".to_owned());
    assert_schema_invalid(&schema_detached_jobs);

    let mut schema_macos_system_user_root = valid_json.clone();
    make_json_system_scope(&mut schema_macos_system_user_root);
    assert_schema_invalid(&schema_macos_system_user_root);

    let mut schema_linux_system_user_root = valid_json.clone();
    schema_linux_system_user_root["platform"]["os"] = Value::String("linux".to_owned());
    make_json_system_scope(&mut schema_linux_system_user_root);
    set_json_paths_root(
        &mut schema_linux_system_user_root,
        "/home/alex-dev/.local/share/styrn",
        '/',
    );
    assert_schema_invalid(&schema_linux_system_user_root);

    let mut schema_windows_user_system_root = valid_json.clone();
    make_json_windows(&mut schema_windows_user_system_root);
    set_json_paths_root(
        &mut schema_windows_user_system_root,
        r"C:\ProgramData\Styrn",
        '\\',
    );
    assert_schema_invalid(&schema_windows_user_system_root);

    let mut schema_windows_system_user_root = valid_json.clone();
    make_json_windows(&mut schema_windows_system_user_root);
    make_json_system_scope(&mut schema_windows_system_user_root);
    set_json_paths_root(
        &mut schema_windows_system_user_root,
        r"C:\Users\alex-dev\AppData\Local\Styrn",
        '\\',
    );
    assert_schema_invalid(&schema_windows_system_user_root);

    let mut schema_scope_mismatch = valid_json;
    schema_scope_mismatch["paths"]["root"] = Value::String("/Users/Shared/Styrn".to_owned());
    assert_schema_invalid(&schema_scope_mismatch);

    let base = MachineManifest::parse_toml(&mac).unwrap();
    for (os, scope, root) in [
        (
            manifest::OperatingSystem::Linux,
            platform::InstallationScope::User,
            "/srv/styrn/nested",
        ),
        (
            manifest::OperatingSystem::Linux,
            platform::InstallationScope::System,
            "/home",
        ),
        (
            manifest::OperatingSystem::Macos,
            platform::InstallationScope::System,
            "/Users",
        ),
    ] {
        let mut invalid = base.clone();
        invalid.platform.os = os;
        invalid.installation.as_mut().unwrap().scope = scope;
        if scope == platform::InstallationScope::System {
            let identity = invalid.worker_identity.as_mut().unwrap();
            identity.mode = manifest::WorkerIdentityMode::Dedicated;
            identity.isolation = platform::WorkerIsolation::DedicatedAccount;
        }
        set_manifest_paths_root(&mut invalid, root, '/');
        assert!(invalid.validate().is_err(), "accepted {root}");
    }
}

#[test]
fn manifest_windows_paths_reject_device_and_normalization_aliases() {
    let mut windows = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap();
    windows.platform.os = manifest::OperatingSystem::Windows;
    let identity = windows.worker_identity.as_mut().unwrap();
    identity.principal_kind = platform::PrincipalKind::WindowsSid;
    identity.principal_id = "S-1-5-21-1-2-3-1001".to_owned();
    set_manifest_paths_root(&mut windows, r"C:\Users\alex-dev\AppData\Local\Styrn", '\\');
    windows.validate().unwrap();

    for invalid_root in [
        r"C:\NUL",
        r"C:\safe\CON",
        r"C:\safe\COM1.txt",
        r"C:\safe\COM¹.txt",
        r"C:\safe\LPT³",
        r"C:\safe\name.",
        r"C:\safe\name ",
        r"C:\safe\bad?name",
        r#"C:\safe\bad"name"#,
    ] {
        let mut invalid = windows.clone();
        set_manifest_paths_root(&mut invalid, invalid_root, '\\');
        assert!(invalid.validate().is_err(), "accepted {invalid_root}");

        let mut json = windows.to_json_value().unwrap();
        set_json_paths_root(&mut json, invalid_root, '\\');
        assert_schema_invalid(&json);
    }

    for (scope, root) in [
        (platform::InstallationScope::User, r"C:\Styrn\nested"),
        (platform::InstallationScope::User, r"C:\ProgramData"),
        (platform::InstallationScope::System, r"C:\Users"),
    ] {
        let mut invalid = windows.clone();
        invalid.installation.as_mut().unwrap().scope = scope;
        if scope == platform::InstallationScope::System {
            let identity = invalid.worker_identity.as_mut().unwrap();
            identity.mode = manifest::WorkerIdentityMode::Dedicated;
            identity.isolation = platform::WorkerIsolation::DedicatedAccount;
        }
        set_manifest_paths_root(&mut invalid, root, '\\');
        assert!(invalid.validate().is_err(), "accepted {root}");

        let mut json = windows.to_json_value().unwrap();
        if scope == platform::InstallationScope::System {
            make_json_system_scope(&mut json);
        }
        set_json_paths_root(&mut json, root, '\\');
        assert_schema_invalid(&json);
    }
}

#[test]
fn controller_only_manifest_may_omit_transport_and_worker_identity() {
    let input = fs::read_to_string("examples/machine.controller-worker.toml")
        .unwrap()
        .replace(
            "roles = [\"controller\", \"worker\"]",
            "roles = [\"controller\"]",
        );
    let input = remove_toml_table(&remove_toml_table(&input, "worker_identity"), "transport");

    let manifest = MachineManifest::parse_toml(&input).unwrap();

    assert!(manifest.worker_identity.is_none());
    assert!(manifest.transport.is_none());
    assert_schema_valid(&manifest.to_json_value().unwrap());
}

#[test]
fn guarded_serialization_rejects_secret_named_dynamic_entries() {
    let valid = fs::read_to_string("examples/machine.controller-worker.toml").unwrap();
    let cases = [
        "PrIvAtE_kEy",
        "private-key",
        "private.key",
        "privateKey",
        "API_kEy",
        "api-key",
        "api.key",
        "apiKey",
        "AuTh_kEy",
        "auth-key",
        "auth.key",
        "authKey",
        "TAILSCALE_auth_key",
        "tailscale-auth-key",
        "tailscale.auth.key",
        "tailscaleAuthKey",
        "ToKeN",
        "to-ken",
        "to.ken",
        "toKen",
        "ACCESS_tOkEn",
        "access-token",
        "access.token",
        "accessToken",
        "PASS_word",
        "pass-word",
        "pass.word",
        "passWord",
        "PASS_phrase",
        "pass-phrase",
        "pass.phrase",
        "passPhrase",
        "SE_cret",
        "se-cret",
        "se.cret",
        "seCret",
        "ID_entity",
        "id-entity",
        "id.entity",
        "idEntity",
    ];

    for (index, key) in cases.into_iter().enumerate() {
        let section = ["capabilities", "agents", "toolchains", "caches"][index % 4];
        let mut manifest = MachineManifest::parse_toml(&valid).unwrap();
        insert_dynamic_key(&mut manifest, section, key);
        for result in [
            manifest.to_toml().map(|_| ()),
            manifest.to_json_value().map(|_| ()),
        ] {
            let error = result.expect_err("{section}.{key} must not serialize");
            let rendered = error.to_string();
            assert!(rendered.contains(section), "{rendered}");
            assert!(rendered.contains(key), "{rendered}");
        }
    }
}

#[test]
fn guarded_serialization_redacts_secret_shaped_dynamic_keys() {
    let valid = fs::read_to_string("examples/machine.controller-worker.toml").unwrap();
    let cases = [
        ("capabilities", "-----BEGIN PRIVATE KEY-----", "private key material"),
        ("agents", "-----BEGIN OPENSSH PRIVATE KEY-----", "private key material"),
        ("toolchains", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHlybiIsInJvbGUiOiJ3b3JrZXIifQ.signaturesegmentwithenoughbase64urlchars123", "JWT-shaped credential"),
        ("caches", "-----BEGIN RSA PRIVATE KEY-----", "private key material"),
    ];

    for (section, secret_key, reason) in cases {
        let mut manifest = MachineManifest::parse_toml(&valid).unwrap();
        insert_dynamic_key(&mut manifest, section, secret_key);
        for result in [
            manifest.to_toml().map(|_| ()),
            manifest.to_json_value().map(|_| ()),
        ] {
            let rendered = result
                .expect_err("secret-shaped dynamic key must not serialize")
                .to_string();
            assert!(rendered.contains(section), "{rendered}");
            assert!(rendered.contains("redacted"), "{rendered}");
            assert!(rendered.contains(reason), "{rendered}");
            assert!(!rendered.contains(secret_key), "{rendered}");
        }
    }
}

#[test]
fn guarded_serialization_rejects_private_key_and_jwt_values_without_echoing_them() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        "-----BEGIN PRIVATE KEY-----",
        "  -----begin private key-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHlybiIsInJvbGUiOiJ3b3JrZXIifQ.signaturesegmentwithenoughbase64urlchars123",
    ];

    for value in cases {
        let mut manifest = MachineManifest::parse_toml(&valid).unwrap();
        manifest
            .agents
            .as_mut()
            .unwrap()
            .get_mut("codex")
            .unwrap()
            .sandbox = Some(value.to_owned());
        for result in [
            manifest.to_toml().map(|_| ()),
            manifest.to_json_value().map(|_| ()),
        ] {
            let error = result.expect_err("secret-shaped value must not serialize");
            let rendered = error.to_string();
            assert!(rendered.contains("agents.codex.sandbox"), "{rendered}");
            assert!(!rendered.contains(value), "{rendered}");
        }
    }
}

#[test]
fn guarded_serialization_allows_public_and_non_secret_near_misses() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenuinePublicKeyMaterial user@host",
        "-----BEGIN PUBLIC KEY-----",
        "api.styrn.dev",
        "1.2.3",
        "tokenizer",
        "public_key_auth",
        "VGhpcy1pcy1sb25nLWJ1dC1iZW5pZ24tYmFzZTY0LWxpa2UtdGV4dC13aXRob3V0LWRvdHM",
        "eyJaaaaaaaaa.abcdefghijkl.abcdefghijkl",
    ];

    for value in cases {
        let manifest = MachineManifest::parse_toml(&valid.replacen(
            "sandbox = \"elevated\"",
            &format!("sandbox = \"{value}\""),
            1,
        ))
        .unwrap();
        assert!(manifest.to_toml().is_ok(), "{value}");
        assert!(manifest.to_json_value().is_ok(), "{value}");
    }
}

#[test]
fn manifest_rejects_hand_authored_invalid_contract_cases() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        (
            "missing schema version",
            remove_line(&valid, "schema_version ="),
        ),
        (
            "wrong schema version",
            valid.replacen("schema_version = 1", "schema_version = 2", 1),
        ),
        (
            "non version seven uuid",
            valid.replacen(
                "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
                "01991f5d-d72f-4b5e-a43d-9fcb61bd3265",
                1,
            ),
        ),
        (
            "non canonical uppercase uuid",
            valid.replacen(
                "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
                "01991F5D-D72F-7B5E-A43D-9FCB61BD3265",
                1,
            ),
        ),
        (
            "duplicate roles",
            valid.replacen(
                "roles = [\"worker\"]",
                "roles = [\"worker\", \"worker\"]",
                1,
            ),
        ),
        (
            "empty roles",
            valid.replacen("roles = [\"worker\"]", "roles = []", 1),
        ),
        (
            "both disk reserve selectors",
            valid.replacen(
                "reserved_disk_bytes = 85899345920",
                "reserved_disk_bytes = 85899345920\nreserved_disk_percent = 15",
                1,
            ),
        ),
        (
            "no disk reserve selector",
            remove_line(&valid, "reserved_disk_bytes ="),
        ),
        (
            "zero positive count",
            valid.replacen("max_heavy_jobs = 1", "max_heavy_jobs = 0", 1),
        ),
        (
            "invalid percent",
            replace_line(
                &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
                "reserved_disk_percent =",
                "reserved_disk_percent = 100",
            ),
        ),
        ("unknown field", format!("{valid}\nunexpected = true\n")),
    ];

    for (name, input) in cases {
        let result = MachineManifest::parse_toml(&input).and_then(|manifest| manifest.validate());
        assert!(result.is_err(), "{name} unexpectedly validated");
    }
}

#[test]
fn schema_valid_optional_desktop_kind_is_accepted() {
    let input = format!(
        "{}\n[desktop]\nenabled = false\n",
        fs::read_to_string("examples/machine.toml")
            .unwrap()
            .replace("[desktop]\nkind = \"rdp\"\nenabled = true", "")
    );
    let manifest = MachineManifest::parse_toml(&input).unwrap();
    assert_schema_valid(&manifest.to_json_value().unwrap());
}

#[test]
fn generated_write_mints_once_and_preserves_identity_across_updates() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let store = MachineManifestStore::new_for_test(&path);
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let first = store.write_generated(&draft).unwrap();
    assert_eq!(first.get_version_num(), 7);
    let mut changed = draft.clone();
    changed.name = "renamed-worker".to_owned();
    let second = store.write_generated(&changed).unwrap();

    assert_eq!(first, second);
    let stored = store.read().unwrap();
    assert!(!stored.machine_id_minted);
    assert_eq!(stored.manifest.machine_id, first);
    assert_eq!(stored.manifest.name, "renamed-worker");
    assert_eq!(
        stored.manifest.installation.unwrap().scope,
        platform::InstallationScope::System
    );
    assert_eq!(stored.manifest.worker_identity.unwrap().name, "build-agent");
}

#[test]
fn user_store_creates_missing_restricted_config_root_without_elevation() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let store = MachineManifestStore::new_user(&path, principal).unwrap();
    let draft = current_user_manifest().without_machine_id();

    let minted = store.write_generated(&draft).unwrap();

    assert_eq!(minted.get_version_num(), 7);
    assert_eq!(store.read().unwrap().manifest.machine_id, minted);
    #[cfg(unix)]
    {
        assert_eq!(fs::metadata(&trusted_root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }
}

#[test]
fn explicit_user_store_does_not_require_canonical_path_environment() {
    const CHILD: &str = "STYRN_EXPLICIT_USER_STORE_NO_HOME_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "explicit_user_store_does_not_require_canonical_path_environment",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("APPDATA")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated explicit-path child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let path = std::env::temp_dir()
        .join(format!("styrn-explicit-user-store-{}", std::process::id()))
        .join("machine.toml");
    MachineManifestStore::new_user(path, current_worker_principal()).unwrap();
}

#[cfg(unix)]
#[test]
fn user_store_rejects_secure_root_below_non_sticky_world_writable_parent_without_partial_state() {
    let temp = TestDir::new();
    let insecure = temp.path().join("insecure");
    let trusted_root = insecure.join("config");
    fs::create_dir(&insecure).unwrap();
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777)).unwrap();
    fs::create_dir(&trusted_root).unwrap();
    fs::set_permissions(&trusted_root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = trusted_root.join("Styrn/machine.toml");
    let store = MachineManifestStore::new_user(&path, current_worker_principal()).unwrap();

    let error = store
        .write_generated(&current_user_manifest().without_machine_id())
        .unwrap_err();

    assert!(matches!(
        error,
        manifest::ManifestError::Security(_) | manifest::ManifestError::Write(_)
    ));
    assert!(!path.parent().unwrap().exists());
    assert_eq!(fs::read_dir(&trusted_root).unwrap().count(), 0);
    fs::set_permissions(insecure, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn scope_mismatch_is_rejected_before_lock_or_directory_creation() {
    let temp = TestDir::new();
    let directory = temp.path().join("system-store");
    let path = directory.join("machine.toml");
    let store = MachineManifestStore::new_system(&path, current_worker_principal()).unwrap();

    let error = store
        .write_generated(&current_user_manifest().without_machine_id())
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "invalid machine manifest: manifest installation scope does not match its store"
    );
    assert!(!directory.exists());
}

#[test]
fn user_store_rejects_a_different_manifest_principal_before_filesystem_mutation() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let store = MachineManifestStore::new_user(&path, current_worker_principal()).unwrap();
    let mut draft = current_user_manifest().without_machine_id();
    let identity = draft.worker_identity.as_mut().unwrap();
    #[cfg(unix)]
    {
        identity.principal_id = if identity.principal_id == "1" {
            "2"
        } else {
            "1"
        }
        .to_owned();
    }
    #[cfg(windows)]
    {
        identity.principal_id = "S-1-5-21-1-2-3-4242".to_owned();
    }
    identity.name = "different-native-account".to_owned();
    draft.transport.as_mut().unwrap().user = Some(identity.name.clone());

    let error = store.write_generated(&draft).unwrap_err();

    assert_eq!(
        error.to_string(),
        "invalid machine manifest: manifest worker identity does not match its store principal"
    );
    assert!(!trusted_root.exists());
}

#[test]
fn user_worker_manifest_store_rejects_an_internally_valid_alternate_root_without_replacement() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let store = MachineManifestStore::new_user(&path, principal.clone()).unwrap();
    let candidate = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &principal,
    )
    .unwrap();
    let machine_id = store.write_generated(candidate.draft()).unwrap();
    let original = fs::read(&path).unwrap();
    let original_identity = platform::private_file_identity(&path).unwrap();
    #[cfg(unix)]
    let original_mode = fs::metadata(&path).unwrap().mode();
    let mut alternate = store.read().unwrap().manifest;
    #[cfg(target_os = "linux")]
    let alternate_root = format!("/home/{}/.local/share/styrn-alternate", principal.name());
    #[cfg(target_os = "macos")]
    let alternate_root = format!(
        "/Users/{}/Library/Application Support/Styrn Alternate",
        principal.name()
    );
    #[cfg(target_os = "windows")]
    let alternate_root = format!(
        r"C:\Users\{}\AppData\Local\Styrn Alternate",
        principal.name()
    );
    let separator = if cfg!(target_os = "windows") {
        '\\'
    } else {
        '/'
    };
    set_manifest_paths_root(&mut alternate, &alternate_root, separator);
    alternate.validate().unwrap();
    let alternate = alternate.without_machine_id();

    let error = store.write_generated(&alternate).unwrap_err();

    assert_eq!(
        error.to_string(),
        "invalid machine manifest: user worker manifest paths do not match the store's canonical layout"
    );
    assert!(!error.to_string().contains(&alternate_root));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        platform::private_file_identity(&path).unwrap(),
        original_identity
    );
    #[cfg(unix)]
    assert_eq!(fs::metadata(&path).unwrap().mode(), original_mode);
    let verified = store.read().unwrap().manifest;
    assert_eq!(verified.machine_id, machine_id);
    assert_no_manifest_temporaries(path.parent().unwrap());
}

#[test]
fn worker_manifest_pre_replace_revalidation_preserves_existing_bytes_on_principal_and_layout_drift()
{
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let worker_root = fs::canonicalize(temp.path()).unwrap().join("worker-root");
    let layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        principal.clone(),
        worker_root,
        None,
    );
    let candidate = manifest::CurrentUserWorkerManifestCandidate::derive_with_layout_for_test(
        &stale_current_user_worker_draft(),
        &principal,
        &layout,
    )
    .unwrap();
    let seed = MachineManifestStore::new_user_with_worker_layout_for_test(
        &path,
        principal.clone(),
        &layout,
    )
    .unwrap();
    let machine_id = seed.write_generated(candidate.draft()).unwrap();
    let original = fs::read(&path).unwrap();
    let original_identity = platform::private_file_identity(&path).unwrap();
    #[cfg(unix)]
    let original_mode = fs::metadata(&path).unwrap().mode();

    let renamed = platform::WorkerPrincipal::new(
        principal.principal_kind(),
        principal.principal_id().to_owned(),
        "renamed-current-user".to_owned(),
        platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    #[cfg(unix)]
    let changed_id = if principal.principal_id() == "1" {
        "2".to_owned()
    } else {
        "1".to_owned()
    };
    #[cfg(windows)]
    let changed_id = "S-1-5-21-111111111-222222222-333333333-4242".to_owned();
    let replaced = platform::WorkerPrincipal::new(
        principal.principal_kind(),
        changed_id,
        principal.name().to_owned(),
        platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    let renamed_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        renamed.clone(),
        layout.root().to_path_buf(),
        None,
    );
    let replaced_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        replaced.clone(),
        layout.root().to_path_buf(),
        None,
    );
    let drifted_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        principal.clone(),
        fs::canonicalize(temp.path())
            .unwrap()
            .join("drifted-worker-root"),
        None,
    );
    let cases = [
        (
            renamed,
            renamed_layout,
            "invalid machine manifest: manifest worker identity does not match its store principal",
        ),
        (
            replaced,
            replaced_layout,
            "invalid machine manifest: manifest worker identity does not match its store principal",
        ),
        (
            principal.clone(),
            drifted_layout,
            "invalid machine manifest: user worker manifest paths do not match the store's canonical layout",
        ),
    ];

    for (observed_principal, observed_layout, expected) in cases {
        let store = MachineManifestStore::new_user_with_worker_layout_for_test(
            &path,
            principal.clone(),
            &layout,
        )
        .unwrap()
        .with_pre_replace_worker_binding_for_test(observed_principal, &observed_layout)
        .unwrap();

        let error = store.write_generated(candidate.draft()).unwrap_err();

        assert_eq!(error.to_string(), expected);
        assert!(!error.to_string().contains("renamed-current-user"));
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(
            platform::private_file_identity(&path).unwrap(),
            original_identity
        );
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().mode(), original_mode);
        assert_eq!(store.read().unwrap().manifest.machine_id, machine_id);
        assert_no_manifest_temporaries(path.parent().unwrap());
    }
}

#[test]
fn exact_user_worker_layout_store_test_binding_rejects_invalid_tuples_before_mutation() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let user_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        principal.clone(),
        fs::canonicalize(temp.path()).unwrap().join("worker-root"),
        None,
    );
    let system_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::System,
        principal.clone(),
        fs::canonicalize(temp.path())
            .unwrap()
            .join("system-worker-root"),
        None,
    );
    let other = platform::WorkerPrincipal::new(
        principal.principal_kind(),
        principal.principal_id().to_owned(),
        "other-layout-principal".to_owned(),
        platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    let mismatched_layout = platform::worker_directory_layout_for_test(
        platform::InstallationScope::User,
        other,
        user_layout.root().to_path_buf(),
        None,
    );

    for (layout, expected) in [
        (
            &system_layout,
            "invalid machine manifest: current-user worker manifest projection requires a user-scope worker draft",
        ),
        (
            &mismatched_layout,
            "invalid machine manifest: current-user worker manifest projection requires the current native principal",
        ),
    ] {
        let error = MachineManifestStore::new_user_with_worker_layout_for_test(
            &path,
            principal.clone(),
            layout,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(!error.to_string().contains("other-layout-principal"));
        assert!(!trusted_root.exists());
    }
}

#[test]
fn user_worker_manifest_store_rejects_candidate_and_stored_hostile_tuple_matrix_without_mutation() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let store = MachineManifestStore::new_user(&path, principal.clone()).unwrap();
    let candidate = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &principal,
    )
    .unwrap();
    let machine_id = store.write_generated(candidate.draft()).unwrap();
    let machine_id_text = machine_id.to_string();
    let valid = store.read().unwrap().manifest;
    let valid_bytes = fs::read(&path).unwrap();
    let valid_identity = platform::private_file_identity(&path).unwrap();
    #[cfg(unix)]
    let valid_mode = fs::metadata(&path).unwrap().mode();

    let cases = [
        (
            WorkerManifestHostileAttack::RenamedPrincipal,
            "invalid machine manifest: manifest worker identity does not match its store principal",
        ),
        (
            WorkerManifestHostileAttack::ReplacedPrincipal,
            "invalid machine manifest: manifest worker identity does not match its store principal",
        ),
        (
            WorkerManifestHostileAttack::DedicatedUserScope,
            "invalid machine manifest: dedicated worker identity requires system installation scope",
        ),
        (
            WorkerManifestHostileAttack::StoreScope,
            "invalid machine manifest: manifest installation scope does not match its store",
        ),
        (
            WorkerManifestHostileAttack::TransportName,
            "invalid machine manifest: transport.user must equal worker_identity.name",
        ),
        (
            WorkerManifestHostileAttack::DetachedChild,
            "invalid machine manifest: paths.jobs must be the jobs child of paths.root",
        ),
        (
            WorkerManifestHostileAttack::AlternateRoot,
            "invalid machine manifest: user worker manifest paths do not match the store's canonical layout",
        ),
        (
            WorkerManifestHostileAttack::NativePlatform,
            "invalid machine manifest: user worker manifest platform does not match the native host",
        ),
    ];

    for (attack, expected) in cases {
        let mut hostile = valid.clone();
        let hostile_value = apply_worker_manifest_hostile_attack(&mut hostile, attack, &principal);
        let hostile_bytes = hostile.to_toml().unwrap().into_bytes();

        let error = store
            .write_generated(&hostile.clone().without_machine_id())
            .unwrap_err();
        assert_eq!(error.to_string(), expected, "{attack:?}");
        assert!(!error.to_string().contains(&hostile_value), "{attack:?}");
        assert_eq!(fs::read(&path).unwrap(), valid_bytes, "{attack:?}");
        assert_eq!(
            platform::private_file_identity(&path).unwrap(),
            valid_identity,
            "{attack:?}"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().mode(),
            valid_mode,
            "{attack:?}"
        );
        platform::verify_manifest_security(
            &path,
            platform::ManifestOwner::User,
            &principal,
            &trusted_root,
        )
        .unwrap();
        assert_eq!(store.read().unwrap().manifest.machine_id, machine_id);
        assert_no_manifest_temporaries(path.parent().unwrap());

        fs::write(&path, &hostile_bytes).unwrap();
        let stored_identity = platform::private_file_identity(&path).unwrap();
        #[cfg(unix)]
        let stored_mode = fs::metadata(&path).unwrap().mode();
        let refresh_error = store.write_generated(candidate.draft()).unwrap_err();
        assert_eq!(refresh_error.to_string(), expected, "stored {attack:?}");
        assert!(
            !refresh_error.to_string().contains(&hostile_value),
            "stored {attack:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), hostile_bytes, "stored {attack:?}");
        assert_eq!(
            platform::private_file_identity(&path).unwrap(),
            stored_identity,
            "stored {attack:?}"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().mode(),
            stored_mode,
            "stored {attack:?}"
        );
        assert_eq!(
            toml::from_str::<toml::Value>(std::str::from_utf8(&hostile_bytes).unwrap()).unwrap()
                ["machine_id"]
                .as_str(),
            Some(machine_id_text.as_str()),
            "stored {attack:?}"
        );
        platform::verify_manifest_security(
            &path,
            platform::ManifestOwner::User,
            &principal,
            &trusted_root,
        )
        .unwrap();
        assert_no_manifest_temporaries(path.parent().unwrap());

        fs::write(&path, &valid_bytes).unwrap();
        assert_eq!(
            platform::private_file_identity(&path).unwrap(),
            valid_identity
        );
    }
}

#[test]
fn controller_only_user_manifest_store_is_not_forced_to_claim_worker_layout() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let store = MachineManifestStore::new_user(&path, principal.clone()).unwrap();
    let mut draft = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &principal,
    )
    .unwrap()
    .into_draft();
    draft.roles = vec![manifest::MachineRole::Controller];
    draft.worker_identity = None;
    draft.transport = None;
    #[cfg(target_os = "linux")]
    let alternate_root = format!("/home/{}/.local/share/controller-state", principal.name());
    #[cfg(target_os = "macos")]
    let alternate_root = format!(
        "/Users/{}/Library/Application Support/Controller State",
        principal.name()
    );
    #[cfg(target_os = "windows")]
    let alternate_root = format!(
        r"C:\Users\{}\AppData\Local\Controller State",
        principal.name()
    );
    set_draft_paths_root(&mut draft, &alternate_root, native_path_separator());

    let machine_id = store.write_generated(&draft).unwrap();
    let stored = store.read().unwrap().manifest;

    assert_eq!(stored.machine_id, machine_id);
    assert_eq!(stored.roles, vec![manifest::MachineRole::Controller]);
    assert!(stored.worker_identity.is_none());
    assert!(stored.transport.is_none());
    assert_eq!(stored.paths.root, alternate_root);
}

#[test]
fn system_dedicated_worker_manifest_store_retains_principal_only_binding() {
    let temp = TestDir::new();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .join("system-store/machine.toml");
    let current = current_worker_principal();
    let dedicated = platform::WorkerPrincipal::new(
        current.principal_kind(),
        current.principal_id().to_owned(),
        current.name().to_owned(),
        platform::WorkerAccountPolicy::Dedicated,
    )
    .unwrap();
    let mut draft = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &current,
    )
    .unwrap()
    .into_draft();
    draft.installation.as_mut().unwrap().scope = platform::InstallationScope::System;
    let identity = draft.worker_identity.as_mut().unwrap();
    identity.mode = manifest::WorkerIdentityMode::Dedicated;
    identity.isolation = platform::WorkerIsolation::DedicatedAccount;
    set_draft_paths_root(&mut draft, system_root_for_test(), native_path_separator());
    let store =
        MachineManifestStore::new_system_with_worker_principal_for_test(&path, dedicated.clone())
            .unwrap();

    let machine_id = store.write_generated(&draft).unwrap();
    let stored = store.read().unwrap().manifest;

    assert_eq!(stored.machine_id, machine_id);
    let stored_identity = stored.worker_identity.unwrap();
    assert_eq!(
        stored_identity.mode,
        manifest::WorkerIdentityMode::Dedicated
    );
    assert_eq!(stored_identity.principal_kind, dedicated.principal_kind());
    assert_eq!(stored_identity.principal_id, dedicated.principal_id());
    assert_eq!(stored_identity.name, dedicated.name());
    assert_eq!(
        stored_identity.isolation,
        platform::WorkerIsolation::DedicatedAccount
    );
    assert_eq!(stored.paths.root, system_root_for_test());
}

#[test]
fn user_worker_manifest_store_mints_once_reruns_identically_and_preserves_policy() {
    let temp = TestDir::new();
    let trusted_root = fs::canonicalize(temp.path()).unwrap().join("config");
    let path = trusted_root.join("Styrn/machine.toml");
    let principal = current_worker_principal();
    let store = MachineManifestStore::new_user(&path, principal.clone()).unwrap();
    let candidate = manifest::CurrentUserWorkerManifestCandidate::derive(
        &stale_current_user_worker_draft(),
        &principal,
    )
    .unwrap();
    let policy = serde_json::to_value(
        candidate
            .draft()
            .resources
            .as_ref()
            .unwrap()
            .policy
            .as_ref()
            .unwrap(),
    )
    .unwrap();

    let machine_id = store.write_generated(candidate.draft()).unwrap();
    assert_eq!(machine_id.get_version_num(), 7);
    let first = fs::read(&path).unwrap();
    assert_eq!(
        store.write_generated(candidate.draft()).unwrap(),
        machine_id
    );
    assert_eq!(fs::read(&path).unwrap(), first);

    let mut observed = candidate.draft().clone();
    observed
        .resources
        .as_mut()
        .unwrap()
        .detected
        .as_mut()
        .unwrap()
        .logical_cpus = Some(73);
    assert_eq!(store.write_generated(&observed).unwrap(), machine_id);
    let observed_bytes = fs::read(&path).unwrap();
    let observed_manifest = store.read().unwrap().manifest;
    assert_eq!(observed_manifest.machine_id, machine_id);
    assert_eq!(
        serde_json::to_value(
            observed_manifest
                .resources
                .as_ref()
                .unwrap()
                .policy
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        policy
    );

    let mut rejected = observed;
    #[cfg(target_os = "linux")]
    let rejected_root = format!("/home/{}/.local/share/styrn-rejected", principal.name());
    #[cfg(target_os = "macos")]
    let rejected_root = format!(
        "/Users/{}/Library/Application Support/Styrn Rejected",
        principal.name()
    );
    #[cfg(target_os = "windows")]
    let rejected_root = format!(
        r"C:\Users\{}\AppData\Local\Styrn Rejected",
        principal.name()
    );
    set_draft_paths_root(&mut rejected, &rejected_root, native_path_separator());
    let error = store.write_generated(&rejected).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid machine manifest: user worker manifest paths do not match the store's canonical layout"
    );
    assert!(!error.to_string().contains(&rejected_root));
    assert_eq!(fs::read(&path).unwrap(), observed_bytes);
    assert_eq!(store.read().unwrap().manifest.machine_id, machine_id);
    assert_no_manifest_temporaries(path.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn generated_write_rejects_a_preexisting_symlink_without_reading_or_replacing_its_target() {
    let temp = TestDir::new();
    let target = temp.path().join("valid-target.toml");
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&target, &original).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let draft = MachineManifest::parse_toml(&String::from_utf8(original.clone()).unwrap())
        .unwrap()
        .without_machine_id();

    assert!(MachineManifestStore::new_for_test(&path)
        .write_generated(&draft)
        .is_err());
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn generated_write_rejects_preexisting_fifo_and_directory_targets_without_blocking() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;

    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let fifo_root = TestDir::new();
    let fifo = fifo_root.path().join("machine.toml");
    let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    assert!(MachineManifestStore::new_for_test(&fifo)
        .write_generated(&draft)
        .is_err());
    assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());

    let directory_root = TestDir::new();
    let directory = directory_root.path().join("machine.toml");
    fs::create_dir(&directory).unwrap();
    assert!(MachineManifestStore::new_for_test(&directory)
        .write_generated(&draft)
        .is_err());
    assert!(fs::symlink_metadata(directory).unwrap().is_dir());
}

#[test]
fn lexically_non_normalized_system_destination_is_rejected_without_mutation() {
    let temp = TestDir::new();
    let invalid_directory = temp.path().join("unused").join("..").join("custom-config");
    let path = invalid_directory.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    assert!(MachineManifestStore::new(&path)
        .write_generated(&draft)
        .is_err());
    assert!(!temp.path().join("unused").exists());
    assert!(!temp.path().join("custom-config").exists());
}

#[cfg(unix)]
#[test]
fn broad_existing_system_directories_are_rejected_without_metadata_mutation() {
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();
    let broad_directories = [
        Path::new("/etc"),
        #[cfg(target_os = "macos")]
        Path::new("/Library/Application Support"),
    ];

    for directory in broad_directories {
        let before = fs::symlink_metadata(directory).unwrap();
        let before_signature = (
            before.file_type().is_symlink(),
            before.uid(),
            before.gid(),
            before.mode(),
        );

        assert!(MachineManifestStore::new(directory.join("machine.toml"))
            .write_generated(&draft)
            .is_err());

        let after = fs::symlink_metadata(directory).unwrap();
        assert_eq!(
            (
                after.file_type().is_symlink(),
                after.uid(),
                after.gid(),
                after.mode(),
            ),
            before_signature,
            "{} metadata changed",
            directory.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn system_destination_rejects_a_symlinked_existing_parent_before_creating_the_leaf() {
    let temp = TestDir::new();
    let real_parent = temp.path().join("real-parent");
    let linked_parent = temp.path().join("linked-parent");
    fs::create_dir(&real_parent).unwrap();
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
    let path = linked_parent.join("styrn").join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    assert!(MachineManifestStore::new(&path)
        .write_generated(&draft)
        .is_err());
    assert!(!real_parent.join("styrn").exists());
    assert!(fs::symlink_metadata(linked_parent)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn system_destination_rejects_a_worker_owned_read_only_parent_without_creating_the_leaf() {
    let temp = TestDir::new();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let path = temp.path().join("custom-config").join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    assert!(
        MachineManifestStore::new_for_test_with_worker_owned_parent(&path)
            .write_generated(&draft)
            .is_err()
    );
    assert!(!temp.path().join("custom-config").exists());
    assert_eq!(fs::metadata(temp.path()).unwrap().mode() & 0o777, 0o555);

    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn existing_override_directory_must_already_be_secure_and_is_never_hardened() {
    let temp = TestDir::new();
    let directory = temp.path().join("custom-config");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    let path = directory.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    assert!(MachineManifestStore::new_override_for_test(&path)
        .write_generated(&draft)
        .is_err());
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o777);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn existing_override_directory_must_be_worker_traversable_and_readable() {
    for insecure_mode in [0o700, 0o750] {
        let temp = TestDir::new();
        let directory = temp.path().join("custom-config");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(insecure_mode)).unwrap();
        let path = directory.join("machine.toml");
        let draft =
            MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
                .unwrap()
                .without_machine_id();

        assert!(MachineManifestStore::new_override_for_test(&path)
            .write_generated(&draft)
            .is_err());
        assert_eq!(
            fs::metadata(&directory).unwrap().mode() & 0o777,
            insecure_mode
        );
        assert!(!path.exists());
    }
}

#[test]
fn failed_hardening_of_a_new_leaf_removes_it_and_allows_a_clean_retry() {
    let temp = TestDir::new();
    let directory = temp.path().join("new-config");
    let path = directory.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let error = MachineManifestStore::new_override_with_failing_hardening(&path)
        .write_generated(&draft)
        .unwrap_err();
    assert!(matches!(error, manifest::ManifestError::Write(_)));
    assert!(!directory.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);

    MachineManifestStore::new_for_test(&path)
        .write_generated(&draft)
        .unwrap();
    assert!(path.is_file());
}

#[test]
fn destination_publication_race_preserves_the_winner_and_cleans_the_staging_leaf() {
    let temp = TestDir::new();
    let directory = temp.path().join("new-config");
    let path = directory.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let error = MachineManifestStore::new_with_directory_publication_race(&path)
        .write_generated(&draft)
        .unwrap_err();

    assert!(matches!(error, manifest::ManifestError::Write(_)));
    assert_eq!(fs::read(directory.join("race-winner")).unwrap(), b"winner");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn staging_cleanup_failure_reports_both_errors_without_poisoning_the_final_leaf() {
    let temp = TestDir::new();
    let directory = temp.path().join("new-config");
    let path = directory.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let error = MachineManifestStore::new_with_directory_publication_and_cleanup_failure(&path)
        .write_generated(&draft)
        .unwrap_err();

    assert!(matches!(
        error,
        manifest::ManifestError::StagingDirectoryCleanup { .. }
    ));
    assert_eq!(fs::read(directory.join("race-winner")).unwrap(), b"winner");
    assert!(!path.exists());
    let staging = fs::read_dir(temp.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .expect("failed cleanup must leave the unpublished staging leaf");
    assert_eq!(
        fs::read(staging.path().join("cleanup-blocker")).unwrap(),
        b"block"
    );
}

#[test]
fn native_directory_publish_never_replaces_an_existing_destination() {
    let temp = TestDir::new();
    let staging_path = temp.path().join("staging");
    let destination = temp.path().join("destination");
    let staging = platform::create_private_manifest_staging_directory(
        &staging_path,
        platform::ManifestOwner::CurrentProcess,
        &current_worker_principal(),
    )
    .unwrap();
    fs::write(staging.path().join("creator"), b"staging").unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("creator"), b"winner").unwrap();

    let error = platform::publish_manifest_directory(&staging, &destination).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(destination.join("creator")).unwrap(), b"winner");
    assert_eq!(
        fs::read(staging.path().join("creator")).unwrap(),
        b"staging"
    );
}

#[test]
fn concurrent_native_directory_publishers_produce_exactly_one_winner() {
    let temp = TestDir::new();
    let destination = temp.path().join("destination");
    let staging = [temp.path().join("staging-a"), temp.path().join("staging-b")].map(|path| {
        platform::create_private_manifest_staging_directory(
            &path,
            platform::ManifestOwner::CurrentProcess,
            &current_worker_principal(),
        )
        .unwrap()
    });
    for (index, staging) in staging.iter().enumerate() {
        fs::write(staging.path().join("creator"), index.to_string()).unwrap();
    }
    let barrier = Arc::new(Barrier::new(staging.len()));
    let (sender, receiver) = mpsc::channel();

    std::thread::scope(|scope| {
        for staging in &staging {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let destination = destination.clone();
            scope.spawn(move || {
                barrier.wait();
                sender
                    .send(platform::publish_manifest_directory(staging, &destination))
                    .unwrap();
            });
        }
    });
    drop(sender);
    let results = receiver.into_iter().collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(std::io::Error::kind)
            .collect::<Vec<_>>(),
        vec![std::io::ErrorKind::AlreadyExists]
    );
    let winner = fs::read_to_string(destination.join("creator")).unwrap();
    assert!(winner == "0" || winner == "1");
    assert!(!staging[winner.parse::<usize>().unwrap()].path().exists());
    assert!(staging[1 - winner.parse::<usize>().unwrap()]
        .path()
        .is_dir());
}

#[cfg(unix)]
#[test]
fn private_staging_leaf_is_0700_at_creation_under_a_permissive_umask() {
    const CHILD_ENV: &str = "STYRN_PRIVATE_STAGING_UMASK_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_staging_leaf_is_0700_at_creation_under_a_permissive_umask",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated umask child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    unsafe {
        libc::umask(0);
    }
    let temp = TestDir::new();
    let staging_path = temp.path().join("staging");
    let staging = platform::create_private_manifest_staging_directory(
        &staging_path,
        platform::ManifestOwner::CurrentProcess,
        &current_worker_principal(),
    )
    .unwrap();

    assert_eq!(fs::metadata(staging.path()).unwrap().mode() & 0o777, 0o700);
}

#[test]
fn system_destination_never_creates_missing_broad_ancestors() {
    let temp = TestDir::new();
    let missing_ancestor = temp.path().join("missing-broad-parent");
    let path = missing_ancestor.join("styrn").join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    assert!(MachineManifestStore::new(&path)
        .write_generated(&draft)
        .is_err());
    assert!(!missing_ancestor.exists());
}

#[cfg(unix)]
#[test]
#[ignore = "environmental: root plus STYRN_UNIX_TEST_WORKER selecting a real unprivileged account"]
fn generated_system_manifest_is_root_owned_and_not_worker_writable() {
    let worker = std::env::var("STYRN_UNIX_TEST_WORKER")
        .expect("STYRN_UNIX_TEST_WORKER must select a real unprivileged account");
    let principal =
        platform::resolve_named_worker_principal(&worker, platform::WorkerAccountPolicy::Dedicated)
            .unwrap();
    let temp = TestDir::new();
    let config = fs::canonicalize(temp.path()).unwrap().join("styrn");
    fs::create_dir(&config).unwrap();
    let path = config.join("machine.toml");
    let draft = system_manifest_for(&principal).without_machine_id();

    MachineManifestStore::new_system(&path, principal)
        .unwrap()
        .write_generated(&draft)
        .unwrap();

    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.uid(), 0, "the manifest owner must be root");
    assert_eq!(metadata.mode() & 0o777, 0o644);
}

#[cfg(unix)]
#[test]
fn deterministic_unix_hardening_sets_readable_file_and_protects_replacement_path() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();
    MachineManifestStore::new_for_test(&path)
        .write_generated(&draft)
        .unwrap();

    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    assert_eq!(fs::metadata(temp.path()).unwrap().mode() & 0o022, 0);
    assert_eq!(
        fs::metadata(temp.path().join(".machine.toml.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("schema_version = 1"));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(platform::verify_manifest_security(
        &path,
        platform::ManifestOwner::CurrentProcess,
        &current_worker_principal(),
        temp.path()
    )
    .is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o775)).unwrap();
    assert!(platform::verify_manifest_security(
        &path,
        platform::ManifestOwner::CurrentProcess,
        &current_worker_principal(),
        temp.path()
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn complete_manifest_read_rejects_insecure_file_directory_and_symlink() {
    let valid = fs::read("examples/machine.toml").unwrap();

    let writable = TestDir::new();
    let writable_path = writable.path().join("machine.toml");
    fs::write(&writable_path, &valid).unwrap();
    fs::set_permissions(&writable_path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(MachineManifestStore::new_for_test(&writable_path)
        .read()
        .is_err());

    fs::set_permissions(&writable_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(writable.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(MachineManifestStore::new_for_test(&writable_path)
        .read()
        .is_err());

    let linked = TestDir::new();
    let target = linked.path().join("target.toml");
    let link = linked.path().join("machine.toml");
    fs::write(&target, valid).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(MachineManifestStore::new_for_test(&link).read().is_err());
}

#[cfg(unix)]
#[test]
fn valid_id_reconciliation_rejects_insecure_input_without_rewriting_it() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

    assert!(MachineManifestStore::new_for_test(&path)
        .reconcile()
        .is_err());

    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o666);
}

#[cfg(unix)]
#[test]
fn generated_write_rejects_an_insecure_existing_manifest_without_preserving_its_identity() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let mut draft = MachineManifest::parse_toml(&String::from_utf8(original.clone()).unwrap())
        .unwrap()
        .without_machine_id();
    draft.name = "must-not-be-written".to_owned();

    assert!(MachineManifestStore::new_for_test(&path)
        .write_generated(&draft)
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o666);
}

#[cfg(unix)]
#[test]
fn security_verification_rejects_worker_writable_grandparent() {
    let temp = TestDir::new();
    let unsafe_ancestor = temp.path().join("unsafe");
    let leaf = unsafe_ancestor.join("config");
    fs::create_dir_all(&leaf).unwrap();
    let path = leaf.join("machine.toml");
    fs::write(&path, fs::read("examples/machine.toml").unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&unsafe_ancestor, fs::Permissions::from_mode(0o777)).unwrap();

    assert!(platform::verify_manifest_security(
        &path,
        platform::ManifestOwner::CurrentProcess,
        &current_worker_principal(),
        temp.path()
    )
    .is_err());

    assert!(
        MachineManifestStore::new_for_test_with_trusted_root(&path, temp.path())
            .read()
            .is_err()
    );
}

#[test]
fn hardening_error_propagates_without_replacing_manifest_or_leaving_a_temporary() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    let draft = MachineManifest::parse_toml(&String::from_utf8(original.clone()).unwrap())
        .unwrap()
        .without_machine_id();

    let error = MachineManifestStore::new_with_failing_hardening(&path)
        .write_generated(&draft)
        .unwrap_err();

    assert!(matches!(error, manifest::ManifestError::Write(_)));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_no_manifest_temporaries(temp.path());
}

#[test]
fn post_replace_verification_error_reports_that_the_destination_changed() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read_to_string("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    let mut draft = MachineManifest::parse_toml(&original)
        .unwrap()
        .without_machine_id();
    draft.name = "replacement-was-installed".to_owned();

    let error = MachineManifestStore::new_with_failing_post_replace_verification(&path)
        .write_generated(&draft)
        .unwrap_err();

    assert!(matches!(
        error,
        manifest::ManifestError::PostReplaceSecurity(_)
    ));
    let replaced = fs::read_to_string(&path).unwrap();
    assert_ne!(replaced, original);
    assert!(replaced.contains("name = \"replacement-was-installed\""));
    assert_no_manifest_temporaries(temp.path());
}

#[cfg(unix)]
#[test]
#[ignore = "environmental: root plus STYRN_UNIX_TEST_WORKER selecting a real unprivileged account"]
fn real_selected_account_can_read_but_cannot_write_or_replace_manifest() {
    use std::ffi::CString;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    assert_eq!(unsafe { libc::geteuid() }, 0, "requires root privileges");
    let worker = std::env::var("STYRN_UNIX_TEST_WORKER")
        .expect("STYRN_UNIX_TEST_WORKER must select a real unprivileged account");
    let principal =
        platform::resolve_named_worker_principal(&worker, platform::WorkerAccountPolicy::Dedicated)
            .unwrap();
    let account = CString::new(worker).unwrap();
    let password = unsafe { libc::getpwnam(account.as_ptr()) };
    assert!(!password.is_null(), "selected worker account must exist");
    let uid = unsafe { (*password).pw_uid };
    let gid = unsafe { (*password).pw_gid };
    assert_ne!(uid, 0, "selected worker must be an unprivileged account");

    let temp = TestDir::new();
    let config = fs::canonicalize(temp.path()).unwrap().join("styrn");
    fs::create_dir(&config).unwrap();
    let path = config.join("machine.toml");
    let draft = system_manifest_for(&principal).without_machine_id();
    MachineManifestStore::new_system(&path, principal)
        .unwrap()
        .write_generated(&draft)
        .unwrap();

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        #[cfg(target_os = "linux")]
        let group_ok = unsafe { libc::initgroups(account.as_ptr(), gid) } == 0;
        #[cfg(target_os = "macos")]
        let group_ok = unsafe {
            libc::initgroups(
                account.as_ptr(),
                libc::c_int::try_from(gid).expect("selected worker gid must fit c_int"),
            )
        } == 0;
        let gid_ok = unsafe { libc::setgid(gid) } == 0;
        let uid_ok = unsafe { libc::setuid(uid) } == 0;
        let readable = fs::read_to_string(&path).is_ok();
        let write_denied = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let replace_denied = fs::rename(&path, config.join("stolen.toml"))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe {
            libc::_exit(i32::from(
                !(group_ok && gid_ok && uid_ok && readable && write_denied && replace_denied),
            ));
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(ExitStatus::from_raw(status).success());
}

#[test]
fn complete_legitimate_manifest_round_trips_and_persists_without_false_positives() {
    let mut manifest = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap();
    let codex = manifest.agents.as_mut().unwrap().get_mut("codex").unwrap();
    codex.command = Some("codex --ask-for-approval never".to_owned());
    codex.sandbox = Some("workspace-write".to_owned());
    codex.shell = Some("zsh".to_owned());
    manifest.pending_actions = Some(vec![manifest::PendingAction {
        id: "first-login".to_owned(),
        severity: manifest::PendingSeverity::Info,
        message: "Complete the first interactive login.".to_owned(),
    }]);

    manifest.validate().unwrap();
    let canonical_toml = manifest.to_toml().unwrap();
    assert_eq!(
        MachineManifest::parse_toml(&canonical_toml)
            .unwrap()
            .to_json_value()
            .unwrap(),
        manifest.to_json_value().unwrap()
    );

    let temp = TestDir::new();
    let store = MachineManifestStore::new_for_test(temp.path().join("machine.toml"));
    let machine_id = store
        .write_generated(&manifest.clone().without_machine_id())
        .unwrap();
    manifest.machine_id = machine_id;
    assert_eq!(
        store.read().unwrap().manifest.to_json_value().unwrap(),
        manifest.to_json_value().unwrap()
    );
}

#[test]
fn duplicate_pending_ids_are_rejected_semantically_without_echo_or_replacement() {
    let sensitive_id = "api_key=duplicate-secret-value";
    let duplicate_fragment = format!(
        r#"
[[pending_actions]]
id = "{sensitive_id}"
severity = "warning"
message = "Complete the first manual step."

[[pending_actions]]
id = "{sensitive_id}"
severity = "error"
message = "Complete the second manual step."
"#
    );
    let duplicate_toml = format!(
        "{}{}",
        fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
        duplicate_fragment
    );
    let error = MachineManifest::parse_toml(&duplicate_toml).unwrap_err();
    assert!(matches!(error, manifest::ManifestError::Validation(_)));
    assert_eq!(
        error.to_string(),
        "invalid machine manifest: pending action identifiers must be unique"
    );
    assert!(!error.to_string().contains(sensitive_id));

    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    fs::write(&path, &duplicate_toml).unwrap();
    let store = MachineManifestStore::new_for_test(&path);
    let stored_error = store.read().unwrap_err();
    assert!(matches!(
        stored_error,
        manifest::ManifestError::Validation(_)
    ));
    assert!(!stored_error.to_string().contains(sensitive_id));
    assert_eq!(fs::read_to_string(&path).unwrap(), duplicate_toml);
    assert_no_manifest_temporaries(temp.path());

    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    let mut draft = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap()
    .without_machine_id();
    draft.pending_actions = Some(vec![
        manifest::PendingAction {
            id: sensitive_id.to_owned(),
            severity: manifest::PendingSeverity::Warning,
            message: "Complete the first manual step.".to_owned(),
        },
        manifest::PendingAction {
            id: sensitive_id.to_owned(),
            severity: manifest::PendingSeverity::Error,
            message: "Complete the second manual step.".to_owned(),
        },
    ]);
    let generated_error = store.write_generated(&draft).unwrap_err();
    assert!(matches!(
        generated_error,
        manifest::ManifestError::Validation(_)
    ));
    assert!(!generated_error.to_string().contains(sensitive_id));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_no_manifest_temporaries(temp.path());

    let mut distinct_objects = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap()
    .to_json_value()
    .unwrap();
    distinct_objects["pending_actions"] = serde_json::json!([
        {"id": "same-id", "severity": "warning", "message": "first"},
        {"id": "same-id", "severity": "error", "message": "second"}
    ]);
    assert!(schema_validator().is_valid(&distinct_objects));
    let mut exact_objects = distinct_objects.clone();
    exact_objects["pending_actions"][1] = exact_objects["pending_actions"][0].clone();
    assert_schema_invalid(&exact_objects);
    let schema: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/machine-v1.schema.json"
    )))
    .unwrap();
    assert!(schema["properties"]["pending_actions"]["description"]
        .as_str()
        .unwrap()
        .contains("runtime semantic validator additionally rejects repeated IDs"));
}

#[test]
fn secret_bearing_generated_writes_preserve_destinations_and_leave_no_temporary_files() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let store = MachineManifestStore::new_for_test(&path);
    let mut secret_draft =
        MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
            .unwrap()
            .without_machine_id();
    secret_draft
        .agents
        .as_mut()
        .unwrap()
        .get_mut("codex")
        .unwrap()
        .command = Some("-----BEGIN PRIVATE KEY-----".to_owned());

    assert!(store.write_generated(&secret_draft).is_err());
    assert!(!path.exists());
    assert_no_manifest_temporaries(temp.path());

    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    assert!(store.write_generated(&secret_draft).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_no_manifest_temporaries(temp.path());
}

#[test]
fn secret_shaped_dynamic_key_generated_writes_preserve_destinations_without_leaking() {
    let secret_keys = [
        "-----BEGIN PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHlybiIsInJvbGUiOiJ3b3JrZXIifQ.signaturesegmentwithenoughbase64urlchars123",
    ];

    for secret_key in secret_keys {
        let temp = TestDir::new();
        let path = temp.path().join("machine.toml");
        let store = MachineManifestStore::new_for_test(&path);
        let mut secret_draft =
            MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
                .unwrap()
                .without_machine_id();
        secret_draft.agents.as_mut().unwrap().insert(
            secret_key.to_owned(),
            manifest::Agent {
                installed: Some(true),
                command: None,
                sandbox: None,
                shell: None,
            },
        );

        let error = store
            .write_generated(&secret_draft)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret_key), "{error}");
        assert!(!path.exists());
        assert_no_manifest_temporaries(temp.path());

        let original = fs::read("examples/machine.toml").unwrap();
        fs::write(&path, &original).unwrap();
        let error = store
            .write_generated(&secret_draft)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret_key), "{error}");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_no_manifest_temporaries(temp.path());
    }
}

#[test]
fn secret_bearing_legacy_manifest_does_not_self_heal_or_rewrite() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let secret_legacy = remove_line(
        &fs::read_to_string("examples/machine.toml")
            .unwrap()
            .replacen(
                "sandbox = \"elevated\"",
                "sandbox = \"-----BEGIN OPENSSH PRIVATE KEY-----\"",
                1,
            ),
        "machine_id =",
    );
    fs::write(&path, &secret_legacy).unwrap();

    assert!(MachineManifestStore::new_for_test(&path)
        .reconcile()
        .is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), secret_legacy);
    assert_no_manifest_temporaries(temp.path());
}

#[test]
fn invalid_generated_write_does_not_repair_an_existing_stage_zero_manifest() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let stage_zero = remove_line(
        &fs::read_to_string("examples/machine.toml").unwrap(),
        "machine_id =",
    );
    fs::write(&path, &stage_zero).unwrap();
    let mut invalid_draft =
        MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
            .unwrap()
            .without_machine_id();
    invalid_draft.schema_version = 2;

    assert!(MachineManifestStore::new_for_test(&path)
        .write_generated(&invalid_draft)
        .is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), stage_zero);
}

#[test]
fn missing_machine_id_repairs_once_and_invalid_input_never_rewrites() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let stage_zero = remove_line(&valid, "machine_id =");
    fs::write(&path, &stage_zero).unwrap();
    let store = MachineManifestStore::new_for_test(&path);

    assert!(store.read().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), stage_zero);

    let repaired = store.reconcile().unwrap();
    assert!(repaired.machine_id_minted);
    assert_eq!(repaired.manifest.machine_id.get_version_num(), 7);
    let bytes_after_repair = fs::read(&path).unwrap();
    let second = store.reconcile().unwrap();
    assert!(!second.machine_id_minted);
    assert_eq!(second.manifest.machine_id, repaired.manifest.machine_id);
    assert_eq!(fs::read(&path).unwrap(), bytes_after_repair);

    let invalid_bytes = b"schema_version = 1\nname = 'bad'\n".to_vec();
    fs::write(&path, &invalid_bytes).unwrap();
    assert!(store.reconcile().is_err());
    assert_eq!(fs::read(&path).unwrap(), invalid_bytes);
}

#[test]
fn complete_manifest_read_is_byte_preserving() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();

    let outcome = MachineManifestStore::new_for_test(&path).read().unwrap();
    assert!(!outcome.machine_id_minted);
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn simultaneous_missing_id_repairs_return_one_persisted_uuid() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    fs::write(
        &path,
        remove_line(
            &fs::read_to_string("examples/machine.toml").unwrap(),
            "machine_id =",
        ),
    )
    .unwrap();
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let (sender, receiver) = mpsc::channel();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let path = path.clone();
            scope.spawn(move || {
                barrier.wait();
                sender
                    .send(
                        MachineManifestStore::new_for_test(path)
                            .reconcile()
                            .unwrap()
                            .manifest
                            .machine_id,
                    )
                    .unwrap();
            });
        }
    });
    drop(sender);
    let ids: Vec<Uuid> = receiver.into_iter().collect();
    assert_eq!(ids.len(), workers);
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]));
}

fn stale_current_user_worker_draft() -> manifest::MachineManifestDraft {
    let mut draft = current_user_manifest().without_machine_id();
    let principal = current_worker_principal();
    let identity = draft.worker_identity.as_mut().unwrap();
    identity.mode = manifest::WorkerIdentityMode::Dedicated;
    identity.principal_kind = principal.principal_kind();
    identity.principal_id = principal.principal_id().to_owned();
    identity.name = "stale-worker".to_owned();
    identity.isolation = platform::WorkerIsolation::DedicatedAccount;

    let transport = draft.transport.as_mut().unwrap();
    transport.host = "sentinel-route.internal".to_owned();
    transport.port = Some(2207);
    transport.user = Some("stale-worker".to_owned());
    draft.controller.as_mut().unwrap().inventory = Some("sentinel-inventory".to_owned());
    draft
        .capabilities
        .as_mut()
        .unwrap()
        .insert("sentinel_operator_capability".to_owned(), false);
    let resources = draft.resources.as_mut().unwrap();
    resources.detected.as_mut().unwrap().logical_cpus = Some(17);
    let policy = resources.policy.as_mut().unwrap();
    policy.reserved_memory_bytes = Some(7_340_032_001);
    policy.reserved_disk_bytes = None;
    policy.reserved_disk_percent = Some(23);
    policy.max_parallel_compile_jobs = Some(5);
    draft.herdr.as_mut().unwrap().session = Some("sentinel-session".to_owned());
    draft.install.as_mut().unwrap().version = Some("9.8.7-test".to_owned());
    draft.pending_actions = Some(vec![manifest::PendingAction {
        id: "sentinel.operator-action".to_owned(),
        severity: manifest::PendingSeverity::Info,
        message: "Complete the operator-owned follow-up.".to_owned(),
    }]);

    #[cfg(unix)]
    set_draft_paths(&mut draft, "/var/tmp/stale-worker-layout", '/');
    #[cfg(windows)]
    set_draft_paths(&mut draft, r"C:\stale-worker-layout", '\\');
    draft
}

fn set_draft_paths(draft: &mut manifest::MachineManifestDraft, root: &str, separator: char) {
    draft.paths.root = root.to_owned();
    draft.paths.repos = format!("{root}{separator}repos");
    draft.paths.jobs = format!("{root}{separator}jobs");
    draft.paths.cache = format!("{root}{separator}cache");
    draft.paths.artifacts = format!("{root}{separator}artifacts");
    draft.paths.logs = format!("{root}{separator}logs");
}

fn draft_snapshot(draft: &manifest::MachineManifestDraft) -> Value {
    serde_json::json!({
        "schema_version": draft.schema_version,
        "name": &draft.name,
        "roles": &draft.roles,
        "platform": &draft.platform,
        "installation": &draft.installation,
        "worker_identity": &draft.worker_identity,
        "transport": &draft.transport,
        "paths": &draft.paths,
        "controller": &draft.controller,
        "worker": &draft.worker,
        "resources": &draft.resources,
        "capabilities": &draft.capabilities,
        "scheduling": &draft.scheduling,
        "tailscale": &draft.tailscale,
        "ssh": &draft.ssh,
        "herdr": &draft.herdr,
        "agents": &draft.agents,
        "toolchains": &draft.toolchains,
        "caches": &draft.caches,
        "install": &draft.install,
        "desktop": &draft.desktop,
        "pending_actions": &draft.pending_actions,
    })
}

fn assert_candidate_rejected_unchanged(
    draft: &manifest::MachineManifestDraft,
    principal: &platform::WorkerPrincipal,
    expected: &str,
) {
    let before = draft_snapshot(draft);
    let error = match manifest::CurrentUserWorkerManifestCandidate::derive(draft, principal) {
        Ok(_) => panic!("invalid draft unexpectedly produced a candidate"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        format!("invalid machine manifest: {expected}")
    );
    assert_eq!(draft_snapshot(draft), before);
}

fn native_operating_system_for_test() -> manifest::OperatingSystem {
    #[cfg(target_os = "linux")]
    return manifest::OperatingSystem::Linux;
    #[cfg(target_os = "macos")]
    return manifest::OperatingSystem::Macos;
    #[cfg(target_os = "windows")]
    return manifest::OperatingSystem::Windows;
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("styrn-manifest-test-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn remove_line(input: &str, starts_with: &str) -> String {
    input
        .lines()
        .filter(|line| !line.trim_start().starts_with(starts_with))
        .collect::<Vec<_>>()
        .join("\n")
}

fn replace_line(input: &str, starts_with: &str, replacement: &str) -> String {
    input
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(starts_with) {
                replacement
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn remove_toml_table(input: &str, table: &str) -> String {
    let header = format!("[{table}]");
    let mut removing = false;
    input
        .lines()
        .filter(|line| {
            if *line == header {
                removing = true;
                return false;
            }
            if removing && line.starts_with('[') {
                removing = false;
            }
            !removing
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_manifest_temporaries(directory: &Path) {
    assert!(
        fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp")),
        "secret rejection must not leave a temporary manifest"
    );
}

fn insert_dynamic_key(manifest: &mut MachineManifest, section: &str, key: &str) {
    match section {
        "capabilities" => {
            manifest
                .capabilities
                .as_mut()
                .unwrap()
                .insert(key.to_owned(), true);
        }
        "agents" => {
            manifest.agents.as_mut().unwrap().insert(
                key.to_owned(),
                manifest::Agent {
                    installed: Some(true),
                    command: None,
                    sandbox: None,
                    shell: None,
                },
            );
        }
        "toolchains" => {
            manifest.toolchains.as_mut().unwrap().insert(
                key.to_owned(),
                manifest::Toolchain {
                    installed: Some(true),
                    host: None,
                    version: None,
                },
            );
        }
        "caches" => {
            manifest.caches.as_mut().unwrap().insert(
                key.to_owned(),
                manifest::Cache {
                    installed: Some(true),
                    max_bytes: None,
                },
            );
        }
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy, Debug)]
enum WorkerManifestHostileAttack {
    RenamedPrincipal,
    ReplacedPrincipal,
    DedicatedUserScope,
    StoreScope,
    TransportName,
    DetachedChild,
    AlternateRoot,
    NativePlatform,
}

fn apply_worker_manifest_hostile_attack(
    manifest: &mut MachineManifest,
    attack: WorkerManifestHostileAttack,
    principal: &platform::WorkerPrincipal,
) -> String {
    match attack {
        WorkerManifestHostileAttack::RenamedPrincipal => {
            let hostile = "hostile-renamed-current-user";
            manifest.worker_identity.as_mut().unwrap().name = hostile.to_owned();
            manifest.transport.as_mut().unwrap().user = Some(hostile.to_owned());
            hostile.to_owned()
        }
        WorkerManifestHostileAttack::ReplacedPrincipal => {
            #[cfg(unix)]
            let hostile = if principal.principal_id() == "1" {
                "2".to_owned()
            } else {
                "1".to_owned()
            };
            #[cfg(windows)]
            let hostile = "S-1-5-21-111111111-222222222-333333333-4242".to_owned();
            manifest.worker_identity.as_mut().unwrap().principal_id = hostile.clone();
            hostile
        }
        WorkerManifestHostileAttack::DedicatedUserScope => {
            let hostile = "dedicated-account";
            let identity = manifest.worker_identity.as_mut().unwrap();
            identity.mode = manifest::WorkerIdentityMode::Dedicated;
            identity.isolation = platform::WorkerIsolation::DedicatedAccount;
            hostile.to_owned()
        }
        WorkerManifestHostileAttack::StoreScope => {
            let hostile = system_root_for_test();
            manifest.installation.as_mut().unwrap().scope = platform::InstallationScope::System;
            set_manifest_paths_root(manifest, hostile, native_path_separator());
            hostile.to_owned()
        }
        WorkerManifestHostileAttack::TransportName => {
            let hostile = "hostile-transport-name";
            manifest.transport.as_mut().unwrap().user = Some(hostile.to_owned());
            hostile.to_owned()
        }
        WorkerManifestHostileAttack::DetachedChild => {
            let hostile = format!(
                "{}{}detached-jobs",
                manifest.paths.root,
                native_path_separator()
            );
            manifest.paths.jobs = hostile.clone();
            hostile
        }
        WorkerManifestHostileAttack::AlternateRoot => {
            #[cfg(target_os = "linux")]
            let hostile = format!("/home/{}/.local/share/styrn-hostile", principal.name());
            #[cfg(target_os = "macos")]
            let hostile = format!(
                "/Users/{}/Library/Application Support/Styrn Hostile",
                principal.name()
            );
            #[cfg(target_os = "windows")]
            let hostile = format!(r"C:\Users\{}\AppData\Local\Styrn Hostile", principal.name());
            set_manifest_paths_root(manifest, &hostile, native_path_separator());
            hostile
        }
        WorkerManifestHostileAttack::NativePlatform => {
            #[cfg(target_os = "linux")]
            {
                let hostile = "/Users/hostile-platform/Library/Application Support/Styrn";
                manifest.platform.os = manifest::OperatingSystem::Macos;
                set_manifest_paths_root(manifest, hostile, '/');
                hostile.to_owned()
            }
            #[cfg(target_os = "macos")]
            {
                let hostile = "/home/hostile-platform/.local/share/styrn";
                manifest.platform.os = manifest::OperatingSystem::Linux;
                set_manifest_paths_root(manifest, hostile, '/');
                hostile.to_owned()
            }
            #[cfg(target_os = "windows")]
            {
                let hostile = "/home/hostile-platform/.local/share/styrn";
                manifest.platform.os = manifest::OperatingSystem::Linux;
                let identity = manifest.worker_identity.as_mut().unwrap();
                identity.principal_kind = platform::PrincipalKind::UnixUid;
                identity.principal_id = "1".to_owned();
                set_manifest_paths_root(manifest, hostile, '/');
                hostile.to_owned()
            }
        }
    }
}

fn native_path_separator() -> char {
    if cfg!(target_os = "windows") {
        '\\'
    } else {
        '/'
    }
}

fn system_root_for_test() -> &'static str {
    #[cfg(target_os = "linux")]
    return "/srv/styrn";
    #[cfg(target_os = "macos")]
    return "/Users/Shared/Styrn";
    #[cfg(target_os = "windows")]
    return r"C:\Styrn";
}

fn set_manifest_paths_root(manifest: &mut MachineManifest, root: &str, separator: char) {
    manifest.paths.root = root.to_owned();
    manifest.paths.repos = format!("{root}{separator}repos");
    manifest.paths.jobs = format!("{root}{separator}jobs");
    manifest.paths.cache = format!("{root}{separator}cache");
    manifest.paths.artifacts = format!("{root}{separator}artifacts");
    manifest.paths.logs = format!("{root}{separator}logs");
}

fn set_draft_paths_root(draft: &mut manifest::MachineManifestDraft, root: &str, separator: char) {
    draft.paths.root = root.to_owned();
    draft.paths.repos = format!("{root}{separator}repos");
    draft.paths.jobs = format!("{root}{separator}jobs");
    draft.paths.cache = format!("{root}{separator}cache");
    draft.paths.artifacts = format!("{root}{separator}artifacts");
    draft.paths.logs = format!("{root}{separator}logs");
}

fn set_json_paths_root(manifest: &mut Value, root: &str, separator: char) {
    for (field, value) in [
        ("root", root.to_owned()),
        ("repos", format!("{root}{separator}repos")),
        ("jobs", format!("{root}{separator}jobs")),
        ("cache", format!("{root}{separator}cache")),
        ("artifacts", format!("{root}{separator}artifacts")),
        ("logs", format!("{root}{separator}logs")),
    ] {
        manifest["paths"][field] = Value::String(value);
    }
}

fn make_json_windows(manifest: &mut Value) {
    manifest["platform"]["os"] = Value::String("windows".to_owned());
    manifest["worker_identity"]["principal_kind"] = Value::String("windows-sid".to_owned());
    manifest["worker_identity"]["principal_id"] = Value::String("S-1-5-21-1-2-3-1001".to_owned());
}

fn make_json_system_scope(manifest: &mut Value) {
    manifest["installation"]["scope"] = Value::String("system".to_owned());
    manifest["worker_identity"]["mode"] = Value::String("dedicated".to_owned());
    manifest["worker_identity"]["isolation"] = Value::String("dedicated-account".to_owned());
}
