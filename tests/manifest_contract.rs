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

    MachineManifestStore::new_for_test(&path)
        .write_generated(&draft)
        .unwrap();
    assert!(path.is_file());
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
#[ignore = "environmental: run as root to verify real system ownership"]
fn generated_system_manifest_is_root_owned_and_not_worker_writable() {
    let temp = TestDir::new();
    let config = temp.path().join("styrn");
    fs::create_dir(&config).unwrap();
    let path = config.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    MachineManifestStore::new(&path)
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
        "styrn",
        temp.path()
    )
    .is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o775)).unwrap();
    assert!(platform::verify_manifest_security(
        &path,
        platform::ManifestOwner::CurrentProcess,
        "styrn",
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
        "styrn",
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
#[ignore = "environmental: run as root on a host with an unprivileged styrn account"]
fn real_styrn_account_can_read_but_cannot_write_or_replace_manifest() {
    use std::ffi::CString;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    assert_eq!(unsafe { libc::geteuid() }, 0, "requires root privileges");
    let account = CString::new("styrn").unwrap();
    let password = unsafe { libc::getpwnam(account.as_ptr()) };
    assert!(!password.is_null(), "requires a real styrn account");
    let uid = unsafe { (*password).pw_uid };
    let gid = unsafe { (*password).pw_gid };
    assert_ne!(uid, 0, "styrn must be an unprivileged account");

    let temp = TestDir::new();
    let config = temp.path().join("styrn");
    fs::create_dir(&config).unwrap();
    let path = config.join("machine.toml");
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();
    MachineManifestStore::new(&path)
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
                libc::c_int::try_from(gid).expect("styrn gid must fit c_int"),
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
