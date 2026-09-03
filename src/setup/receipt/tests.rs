use super::*;
use std::sync::{Arc, Barrier};
use std::{fs, path::PathBuf};

fn pending_receipt_value() -> serde_json::Value {
    let mut pending = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    pending["entries"][0]["status"] = serde_json::json!("pending");
    pending["entries"][0]["privilege_used"] = serde_json::json!("none");
    for field in [
        "directories_created",
        "files_created",
        "files_modified",
        "services",
        "accounts",
        "registry_keys",
        "firewall_rules",
    ] {
        pending["entries"][0][field] = serde_json::json!([]);
    }
    pending["entries"][0]["download_provenance"] = serde_json::Value::Null;
    pending
}

fn worker_directory_receipt_value() -> serde_json::Value {
    #[cfg(not(target_os = "windows"))]
    let (principal_kind, principal_id, root, path) = (
        "unix-uid",
        "501",
        "/home/alex/.local/share/styrn",
        "/home/alex/.local/share/styrn/jobs",
    );
    #[cfg(target_os = "windows")]
    let (principal_kind, principal_id, root, path) = (
        "windows-sid",
        "S-1-5-21-1-2-3-1001",
        r"C:\Users\alex\AppData\Local\Styrn",
        r"C:\Users\alex\AppData\Local\Styrn\jobs",
    );

    serde_json::json!({
        "schema_version": 1,
        "installation_scope": "user",
        "entries": [{
            "entry_id": "019cafd0-5c00-7000-8000-000000000001",
            "action": {
                "type": "worker_directory",
                "parameters": {
                    "action_id": "identity.directory.jobs",
                    "installation_scope": "user",
                    "principal": {
                        "account_policy": "current-user",
                        "principal_kind": principal_kind,
                        "principal_id": principal_id,
                        "name": "alex"
                    },
                    "root": root,
                    "node": { "type": "jobs" },
                    "path": path
                }
            },
            "timestamp": "2026-09-02T10:00:00Z",
            "privilege_used": "none",
            "directories_created": [{ "path": path }],
            "files_created": [],
            "files_modified": [],
            "services": [],
            "accounts": [],
            "registry_keys": [],
            "firewall_rules": [],
            "download_provenance": null,
            "status": "applied"
        }]
    })
}

fn dedicated_account_prerequisite_receipt_value() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "installation_scope": "user",
        "entries": [{
            "entry_id": "019cafd0-5c00-7000-8000-000000000001",
            "action": {
                "type": "dedicated_account_prerequisite",
                "parameters": {
                    "action_id": "identity.account.dedicated.sha256-7f81291a9c35cb94e74c8794e4c1ea1c0966b92fc67a72490ef0df956320a394",
                    "target_scope": "system",
                    "selector": "build-agent"
                }
            },
            "timestamp": "2026-09-02T10:00:00Z",
            "privilege_used": "none",
            "directories_created": [],
            "files_created": [],
            "files_modified": [],
            "services": [],
            "accounts": [],
            "registry_keys": [],
            "firewall_rules": [],
            "download_provenance": null,
            "status": "pending"
        }]
    })
}

fn deferred_system_action_receipt_value() -> serde_json::Value {
    #[cfg(not(target_os = "windows"))]
    let (principal_kind, principal_id) = ("unix-uid", "2001");
    #[cfg(target_os = "windows")]
    let (principal_kind, principal_id) = ("windows-sid", "S-1-5-21-1-2-3-2001");

    serde_json::json!({
        "schema_version": 1,
        "installation_scope": "user",
        "entries": [{
            "entry_id": "019cafd0-5c00-7000-8000-000000000001",
            "action": {
                "type": "deferred_system_action",
                "parameters": {
                    "action_id": "identity.directory.jobs",
                    "target_scope": "system",
                    "target_principal": {
                        "account_policy": "dedicated",
                        "principal_kind": principal_kind,
                        "principal_id": principal_id,
                        "name": "build-agent"
                    },
                    "parameter_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            },
            "timestamp": "2026-09-02T10:00:00Z",
            "privilege_used": "none",
            "directories_created": [],
            "files_created": [],
            "files_modified": [],
            "services": [],
            "accounts": [],
            "registry_keys": [],
            "firewall_rules": [],
            "download_provenance": null,
            "status": "pending"
        }]
    })
}

fn succeeded_intent_fixture(
    store: &ReceiptStore,
    fixture: &ReceiptFixture,
) -> (crate::setup::action::JournalAuthority, ReceiptIntent) {
    let authority = crate::setup::action::JournalAuthority::for_test();
    let entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    let path = fixture
        .receipt_path()
        .parent()
        .unwrap()
        .join(".receipt.json.transaction.019cafd0-5c00-7000-8000-000000000001.json");
    let document = ReceiptIntentDocument {
        schema_version: SCHEMA_VERSION,
        installation_scope: InstallationScope::System,
        phase: ReceiptIntentPhase::Succeeded,
        entry: entry.clone(),
    };
    let mut file =
        crate::platform::create_private_file(&path, store.owner, store.worker_principal()).unwrap();
    let identity = crate::platform::private_file_identity_from_handle(&file).unwrap();
    file.write_all(&document.to_json().unwrap()).unwrap();
    file.sync_all().unwrap();
    (
        authority,
        ReceiptIntent {
            entry,
            path,
            phase: ReceiptIntentPhase::Succeeded,
            identity,
        },
    )
}

#[test]
fn receipt_succeeded_append_precedes_intent_retirement() {
    let fixture = ReceiptFixture::new("succeeded-append-before-retire");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let (authority, intent) = succeeded_intent_fixture(&store, &fixture);
    let session = store.begin_apply(&authority).unwrap();

    session
        .append_succeeded_intent(&intent, &authority)
        .unwrap();

    assert!(intent.path.exists());
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    session
        .retire_finalized_intent(&intent, &authority)
        .unwrap();
    assert!(!intent.path.exists());
}

#[test]
fn receipt_wire_is_unchanged_by_finalize_split() {
    let fixture = ReceiptFixture::new("succeeded-split-wire");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let (authority, intent) = succeeded_intent_fixture(&store, &fixture);
    let intent_wire_before = fs::read(&intent.path).unwrap();
    let expected_receipt_wire = ReceiptDocument::from_json(COMPLETE_RECEIPT.as_bytes())
        .unwrap()
        .to_json()
        .unwrap();
    let session = store.begin_apply(&authority).unwrap();

    session
        .append_succeeded_intent(&intent, &authority)
        .unwrap();

    assert_eq!(
        fs::read(fixture.receipt_path()).unwrap(),
        expected_receipt_wire
    );
    assert_eq!(fs::read(&intent.path).unwrap(), intent_wire_before);
    session
        .retire_finalized_intent(&intent, &authority)
        .unwrap();
    assert_eq!(
        fs::read(fixture.receipt_path()).unwrap(),
        expected_receipt_wire
    );
}

#[cfg(not(target_os = "windows"))]
const COMPLETE_RECEIPT: &str = r#"{
  "schema_version": 1,
  "installation_scope": "system",
  "entries": [
    {
      "entry_id": "019cafd0-5c00-7000-8000-000000000001",
      "action": {
        "type": "foundation",
        "parameters": {
          "action_id": "test.first"
        }
      },
      "timestamp": "2026-09-02T10:00:00Z",
      "privilege_used": "root",
      "directories_created": [],
      "files_created": [
        {
          "path": "/opt/styrn/bin/tool",
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ],
      "files_modified": [
        {
          "path": "/etc/styrn/config.toml",
          "before_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "backup_path": "/var/lib/styrn/backups/config.toml"
        }
      ],
      "services": [
        { "name": "styrnd" }
      ],
      "accounts": [
        { "name": "styrn" }
      ],
      "registry_keys": [
        { "path": "HKLM\\Software\\Styrn" }
      ],
      "firewall_rules": [
        { "name": "Styrn SSH" }
      ],
      "download_provenance": {
        "url": "https://downloads.example.test/styrn/tool-1.2.3",
        "version": "1.2.3",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      },
      "status": "applied"
    }
  ]
}"#;

#[cfg(target_os = "windows")]
const COMPLETE_RECEIPT: &str = r#"{
  "schema_version": 1,
  "installation_scope": "system",
  "entries": [
    {
      "entry_id": "019cafd0-5c00-7000-8000-000000000001",
      "action": {
        "type": "foundation",
        "parameters": {
          "action_id": "test.first"
        }
      },
      "timestamp": "2026-09-02T10:00:00Z",
      "privilege_used": "admin",
      "directories_created": [],
      "files_created": [
        {
          "path": "C:\\ProgramData\\Styrn\\bin\\tool.exe",
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ],
      "files_modified": [
        {
          "path": "C:\\ProgramData\\Styrn\\config.toml",
          "before_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "backup_path": "C:\\ProgramData\\Styrn\\backups\\config.toml"
        }
      ],
      "services": [
        { "name": "styrnd" }
      ],
      "accounts": [
        { "name": "build-agent" }
      ],
      "registry_keys": [
        { "path": "HKLM\\Software\\Styrn" }
      ],
      "firewall_rules": [
        { "name": "Styrn SSH" }
      ],
      "download_provenance": {
        "url": "https://downloads.example.test/styrn/tool-1.2.3",
        "version": "1.2.3",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      },
      "status": "applied"
    }
  ]
}"#;

#[test]
fn complete_v1_document_validates_and_round_trips_deterministically() {
    let document = ReceiptDocument::from_json(COMPLETE_RECEIPT.as_bytes()).unwrap();

    assert_eq!(document.schema_version(), 1);
    assert_eq!(document.entries().len(), 1);
    assert_eq!(document.entries()[0].status(), ReceiptStatus::Applied);

    let first = document.to_json().unwrap();
    let second = ReceiptDocument::from_json(&first)
        .unwrap()
        .to_json()
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first).unwrap(),
        serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap()
    );
}

#[test]
fn worker_directory_receipt_round_trips_closed_parameters_and_directory_effect() {
    let value = worker_directory_receipt_value();

    let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let serialized =
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap();

    assert_eq!(serialized, value);
    assert_eq!(
        serialized["entries"][0]["action"]["parameters"]["node"],
        serde_json::json!({ "type": "jobs" })
    );
    assert_eq!(
        serialized["entries"][0]["directories_created"],
        serde_json::json!([{ "path": value["entries"][0]["action"]["parameters"]["path"] }])
    );
}

#[test]
fn dedicated_system_worker_directory_receipt_accepts_only_the_native_privileged_pair() {
    let mut value = worker_directory_receipt_value();
    value["installation_scope"] = serde_json::json!("system");
    value["entries"][0]["action"]["parameters"]["installation_scope"] = serde_json::json!("system");
    value["entries"][0]["action"]["parameters"]["principal"]["account_policy"] =
        serde_json::json!("dedicated");
    #[cfg(not(target_os = "windows"))]
    {
        value["entries"][0]["action"]["parameters"]["root"] =
            serde_json::json!("/var/lib/styrn/workers/build-agent");
        value["entries"][0]["action"]["parameters"]["path"] =
            serde_json::json!("/var/lib/styrn/workers/build-agent/jobs");
        value["entries"][0]["directories_created"][0]["path"] =
            serde_json::json!("/var/lib/styrn/workers/build-agent/jobs");
        value["entries"][0]["privilege_used"] = serde_json::json!("root");
    }
    #[cfg(target_os = "windows")]
    {
        value["entries"][0]["action"]["parameters"]["root"] =
            serde_json::json!(r"C:\ProgramData\Styrn\workers\build-agent");
        value["entries"][0]["action"]["parameters"]["path"] =
            serde_json::json!(r"C:\ProgramData\Styrn\workers\build-agent\jobs");
        value["entries"][0]["directories_created"][0]["path"] =
            serde_json::json!(r"C:\ProgramData\Styrn\workers\build-agent\jobs");
        value["entries"][0]["privilege_used"] = serde_json::json!("admin");
    }

    let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap(),
        value
    );
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/setup-receipt-v1.schema.json"
    )))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&value));

    let mut crossed = value;
    crossed["entries"][0]["action"]["parameters"]["principal"]["account_policy"] =
        serde_json::json!("current-user");
    assert!(!validator.is_valid(&crossed));
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&crossed).unwrap()).unwrap_err(),
        ReceiptError::InvalidWorkerDirectoryAction
    );
}

#[test]
fn deferred_system_action_receipt_is_user_scoped_pending_and_nonowning() {
    let value = deferred_system_action_receipt_value();
    let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    document
        .validate_worker_principal(&fixture_worker_principal())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap(),
        value
    );

    for (pointer, replacement) in [
        ("/installation_scope", serde_json::json!("system")),
        ("/entries/0/status", serde_json::json!("applied")),
        ("/entries/0/privilege_used", serde_json::json!("root")),
        (
            "/entries/0/action/parameters/target_scope",
            serde_json::json!("user"),
        ),
        (
            "/entries/0/action/parameters/target_principal/account_policy",
            serde_json::json!("current-user"),
        ),
    ] {
        let mut hostile = deferred_system_action_receipt_value();
        *hostile.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            ReceiptDocument::from_json(&serde_json::to_vec(&hostile).unwrap()).is_err(),
            "runtime accepted hostile deferred action at {pointer}"
        );
    }

    let mut owning = deferred_system_action_receipt_value();
    owning["entries"][0]["directories_created"] =
        serde_json::json!([{ "path": "/var/lib/styrn/workers/build-agent/jobs" }]);
    assert!(ReceiptDocument::from_json(&serde_json::to_vec(&owning).unwrap()).is_err());
}

#[test]
fn deferred_system_action_schema_is_user_scoped_pending_and_nonowning() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/setup-receipt-v1.schema.json"
    )))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let base = deferred_system_action_receipt_value();
    assert!(validator.is_valid(&base));

    for (pointer, replacement) in [
        ("/installation_scope", serde_json::json!("system")),
        ("/entries/0/status", serde_json::json!("applied")),
        ("/entries/0/privilege_used", serde_json::json!("admin")),
        (
            "/entries/0/action/parameters/target_scope",
            serde_json::json!("user"),
        ),
        (
            "/entries/0/action/parameters/target_principal/account_policy",
            serde_json::json!("current-user"),
        ),
    ] {
        let mut hostile = deferred_system_action_receipt_value();
        *hostile.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            !validator.is_valid(&hostile),
            "schema accepted hostile deferred action at {pointer}"
        );
    }
}

#[test]
fn dedicated_account_prerequisite_receipt_round_trips_only_as_current_user_pending() {
    let value = dedicated_account_prerequisite_receipt_value();
    let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();

    document
        .validate_worker_principal(&fixture_worker_principal())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap(),
        value
    );

    let current = fixture_worker_principal();
    let dedicated = crate::platform::WorkerPrincipal::new(
        current.principal_kind(),
        current.principal_id(),
        current.name(),
        crate::platform::WorkerAccountPolicy::Dedicated,
    )
    .unwrap();
    assert_eq!(
        document.validate_worker_principal(&dedicated).unwrap_err(),
        ReceiptError::InvalidWorkerPrincipal
    );
}

#[test]
fn dedicated_account_prerequisite_receipt_rejects_scope_state_and_ownership_claims() {
    let base = dedicated_account_prerequisite_receipt_value();
    let mut hostile = Vec::new();

    let mut system = base.clone();
    system["installation_scope"] = serde_json::json!("system");
    hostile.push(system);
    for status in ["applied", "adopted"] {
        let mut value = base.clone();
        value["entries"][0]["status"] = serde_json::json!(status);
        hostile.push(value);
    }
    let mut privileged = base.clone();
    privileged["entries"][0]["privilege_used"] = serde_json::json!("root");
    hostile.push(privileged);
    let mut owns_account = base.clone();
    owns_account["entries"][0]["accounts"] = serde_json::json!([{ "name": "build-agent" }]);
    hostile.push(owns_account);
    let mut owns_directory = base.clone();
    owns_directory["entries"][0]["directories_created"] =
        serde_json::json!([{ "path": "/home/build-agent" }]);
    hostile.push(owns_directory);
    let mut wrong_target = base.clone();
    wrong_target["entries"][0]["action"]["parameters"]["target_scope"] = serde_json::json!("user");
    hostile.push(wrong_target);
    let mut ambiguous_selector = base.clone();
    ambiguous_selector["entries"][0]["action"]["parameters"]["selector"] =
        serde_json::json!("../build-agent");
    hostile.push(ambiguous_selector);
    let mut mismatched_digest = base.clone();
    mismatched_digest["entries"][0]["action"]["parameters"]["action_id"] = serde_json::json!(
        "identity.account.dedicated.sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    hostile.push(mismatched_digest);
    let mut principal_claim = base;
    principal_claim["entries"][0]["action"]["parameters"]["principal_id"] =
        serde_json::json!("2001");
    hostile.push(principal_claim);

    for value in hostile {
        assert!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "hostile prerequisite receipt was accepted: {value}"
        );
    }
}

#[test]
fn dedicated_account_prerequisite_schema_requires_user_pending_nonowning_shape() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/setup-receipt-v1.schema.json"
    )))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let base = dedicated_account_prerequisite_receipt_value();
    assert!(validator.is_valid(&base));

    let mut hostile = Vec::new();
    let mut system = base.clone();
    system["installation_scope"] = serde_json::json!("system");
    hostile.push(system);
    let mut applied = base.clone();
    applied["entries"][0]["status"] = serde_json::json!("applied");
    hostile.push(applied);
    let mut privileged = base.clone();
    privileged["entries"][0]["privilege_used"] = serde_json::json!("root");
    hostile.push(privileged);
    let mut owns_account = base.clone();
    owns_account["entries"][0]["accounts"] = serde_json::json!([{ "name": "build-agent" }]);
    hostile.push(owns_account);
    let mut wrong_target = base.clone();
    wrong_target["entries"][0]["action"]["parameters"]["target_scope"] = serde_json::json!("user");
    hostile.push(wrong_target);
    let mut ambiguous = base.clone();
    ambiguous["entries"][0]["action"]["parameters"]["selector"] =
        serde_json::json!("../build-agent");
    hostile.push(ambiguous);
    let mut principal_claim = base;
    principal_claim["entries"][0]["action"]["parameters"]["principal_id"] =
        serde_json::json!("2001");
    hostile.push(principal_claim);

    for value in hostile {
        assert!(!validator.is_valid(&value), "schema accepted {value}");
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn worker_directory_support_node_retains_its_ordinal_and_exact_ancestor_path() {
    let mut value = worker_directory_receipt_value();
    value["entries"][0]["action"]["parameters"]["action_id"] =
        serde_json::json!("identity.directory.support-0");
    value["entries"][0]["action"]["parameters"]["node"] =
        serde_json::json!({ "type": "support", "ordinal": 0 });
    value["entries"][0]["action"]["parameters"]["path"] = serde_json::json!("/home/alex/.local");
    value["entries"][0]["directories_created"][0]["path"] = serde_json::json!("/home/alex/.local");

    let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();

    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap(),
        value
    );
}

#[test]
fn worker_directory_native_support_validation_accepts_every_available_node() {
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let layout =
        crate::platform::resolve_worker_directory_layout(InstallationScope::User, &principal, None)
            .unwrap();
    let support_nodes = layout
        .materialization_nodes()
        .into_iter()
        .filter(|node| matches!(node, crate::platform::WorkerDirectoryNode::Support { .. }))
        .collect::<Vec<_>>();

    for node in &support_nodes {
        let crate::platform::WorkerDirectoryNode::Support { ordinal } = node else {
            unreachable!("support filter must retain only support nodes")
        };
        let path = layout.path_for_node(*node).unwrap();
        let value = worker_directory_receipt_for_layout(&layout, &principal, *ordinal, &path);
        let document = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        document.validate_worker_directory_layout(&layout).unwrap();
    }
}

#[test]
fn worker_directory_support_validation_covers_zero_one_and_many_exact_nodes() {
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    #[cfg(unix)]
    let cases = [
        ("/native/existing/styrn", None, 0_usize),
        ("/native/profile/first/styrn", Some("/native/profile"), 1),
        (
            "/native/profile/first/second/third/styrn",
            Some("/native/profile"),
            3,
        ),
    ];
    #[cfg(target_os = "windows")]
    let cases = [
        (r"C:\native\existing\Styrn", None, 0_usize),
        (
            r"C:\native\profile\first\Styrn",
            Some(r"C:\native\profile"),
            1,
        ),
        (
            r"C:\native\profile\first\second\third\Styrn",
            Some(r"C:\native\profile"),
            3,
        ),
    ];
    let mut many = None;
    for (root, anchor, expected_support_count) in cases {
        let layout = crate::platform::worker_directory_layout_for_test(
            InstallationScope::User,
            principal.clone(),
            PathBuf::from(root),
            anchor.map(PathBuf::from),
        );
        let support_nodes = layout
            .materialization_nodes()
            .into_iter()
            .filter(|node| matches!(node, crate::platform::WorkerDirectoryNode::Support { .. }))
            .collect::<Vec<_>>();
        assert_eq!(support_nodes.len(), expected_support_count);
        for node in support_nodes {
            let crate::platform::WorkerDirectoryNode::Support { ordinal } = node else {
                unreachable!("support filter must retain only support nodes")
            };
            let path = layout.path_for_node(node).unwrap();
            let value = worker_directory_receipt_for_layout(&layout, &principal, ordinal, &path);
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap())
                .unwrap()
                .validate_worker_directory_layout(&layout)
                .unwrap();
        }
        if expected_support_count == 3 {
            many = Some(layout);
        }
    }

    let layout = many.unwrap();
    let different_plausible_ancestor = layout
        .path_for_node(crate::platform::WorkerDirectoryNode::Support { ordinal: 1 })
        .unwrap();
    let forged =
        worker_directory_receipt_for_layout(&layout, &principal, 0, &different_plausible_ancestor);
    let document = ReceiptDocument::from_json(&serde_json::to_vec(&forged).unwrap()).unwrap();
    assert_eq!(
        document
            .validate_worker_directory_layout(&layout)
            .unwrap_err(),
        ReceiptError::InvalidWorkerDirectoryAction
    );
}

fn worker_directory_receipt_for_layout(
    layout: &crate::platform::WorkerDirectoryLayout,
    principal: &crate::platform::WorkerPrincipal,
    ordinal: u16,
    path: &std::path::Path,
) -> serde_json::Value {
    let mut value = worker_directory_receipt_value();
    value["entries"][0]["action"]["parameters"]["action_id"] =
        serde_json::json!(format!("identity.directory.support-{ordinal}"));
    value["entries"][0]["action"]["parameters"]["principal"] = serde_json::json!({
        "account_policy": "current-user",
        "principal_kind": principal.principal_kind(),
        "principal_id": principal.principal_id(),
        "name": principal.name(),
    });
    value["entries"][0]["action"]["parameters"]["root"] =
        serde_json::json!(layout.root().to_string_lossy());
    value["entries"][0]["action"]["parameters"]["node"] =
        serde_json::json!({ "type": "support", "ordinal": ordinal });
    value["entries"][0]["action"]["parameters"]["path"] = serde_json::json!(path.to_string_lossy());
    value["entries"][0]["directories_created"][0]["path"] =
        serde_json::json!(path.to_string_lossy());
    value
}

#[test]
fn worker_directory_legacy_missing_directories_field_reads_empty_and_new_writes_include_it() {
    let mut legacy = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    legacy["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("directories_created");

    let document = ReceiptDocument::from_json(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    let serialized =
        serde_json::from_slice::<serde_json::Value>(&document.to_json().unwrap()).unwrap();

    assert_eq!(
        serialized["entries"][0]["directories_created"],
        serde_json::json!([])
    );
}

#[test]
fn legacy_v1_publication_digest_fallback_excludes_directory_actions_and_effects() {
    let foundation = ReceiptDocument::from_json(COMPLETE_RECEIPT.as_bytes()).unwrap();
    let old_foundation_digest = legacy_v1_receipt_document_digest(&foundation).unwrap();
    assert!(
        pending_publication_prefix_digest_matches(&foundation, &old_foundation_digest).unwrap()
    );

    let mut with_directory_effect = foundation;
    #[cfg(not(target_os = "windows"))]
    let directory_path = "/opt/styrn/support";
    #[cfg(target_os = "windows")]
    let directory_path = r"C:\ProgramData\Styrn\support";
    with_directory_effect.entries[0]
        .directories_created
        .push(CreatedDirectory {
            path: RecordedPath(directory_path.to_owned()),
        });
    assert!(!pending_publication_prefix_digest_matches(
        &with_directory_effect,
        &old_foundation_digest
    )
    .unwrap());

    let mut worker_value = worker_directory_receipt_value();
    worker_value["entries"][0]["status"] = serde_json::json!("pending");
    worker_value["entries"][0]["directories_created"] = serde_json::json!([]);
    let worker = ReceiptDocument::from_json(&serde_json::to_vec(&worker_value).unwrap()).unwrap();
    let hypothetical_old_worker_digest = legacy_v1_receipt_document_digest(&worker).unwrap();
    assert!(
        !pending_publication_prefix_digest_matches(&worker, &hypothetical_old_worker_digest)
            .unwrap()
    );
}

#[test]
fn worker_directory_receipt_rejects_detached_scope_policy_principal_node_and_effect_data() {
    let base = worker_directory_receipt_value();
    let mut cases = Vec::new();

    let mut detached = base.clone();
    #[cfg(not(target_os = "windows"))]
    let detached_path = "/home/alex/.local/share/other/jobs";
    #[cfg(target_os = "windows")]
    let detached_path = r"C:\Users\alex\AppData\Local\Other\jobs";
    detached["entries"][0]["action"]["parameters"]["path"] = serde_json::json!(detached_path);
    detached["entries"][0]["directories_created"][0]["path"] = serde_json::json!(detached_path);
    cases.push(("detached path", detached));

    let mut wrong_scope = base.clone();
    wrong_scope["entries"][0]["action"]["parameters"]["installation_scope"] =
        serde_json::json!("system");
    cases.push(("wrong scope", wrong_scope));

    let mut wrong_policy = base.clone();
    wrong_policy["entries"][0]["action"]["parameters"]["principal"]["account_policy"] =
        serde_json::json!("dedicated");
    cases.push(("wrong policy", wrong_policy));

    let mut wrong_principal = base.clone();
    wrong_principal["entries"][0]["action"]["parameters"]["principal"]["principal_id"] =
        serde_json::json!("0");
    cases.push(("wrong principal", wrong_principal));

    let mut wrong_action_id = base.clone();
    wrong_action_id["entries"][0]["action"]["parameters"]["action_id"] =
        serde_json::json!("identity.directory.cache");
    cases.push(("wrong action id", wrong_action_id));

    let mut detached_effect = base;
    detached_effect["entries"][0]["directories_created"][0]["path"] =
        detached_effect["entries"][0]["action"]["parameters"]["root"].clone();
    cases.push(("detached effect", detached_effect));

    for (label, value) in cases {
        assert!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "worker directory receipt accepted {label}"
        );
    }

    #[cfg(not(target_os = "windows"))]
    let (principal_kind, principal_id) = (crate::platform::PrincipalKind::UnixUid, "501");
    #[cfg(target_os = "windows")]
    let (principal_kind, principal_id) = (
        crate::platform::PrincipalKind::WindowsSid,
        "S-1-5-21-1-2-3-1001",
    );
    let expected_principal = crate::platform::WorkerPrincipal::new(
        principal_kind,
        principal_id,
        "alex",
        crate::platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    for (pointer, replacement) in [
        (
            "/entries/0/action/parameters/principal/principal_id",
            #[cfg(not(target_os = "windows"))]
            "502",
            #[cfg(target_os = "windows")]
            "S-1-5-21-1-2-3-1002",
        ),
        (
            "/entries/0/action/parameters/principal/name",
            "different-user",
        ),
    ] {
        let mut mismatch = worker_directory_receipt_value();
        *mismatch.pointer_mut(pointer).unwrap() = serde_json::json!(replacement);
        let document = ReceiptDocument::from_json(&serde_json::to_vec(&mismatch).unwrap()).unwrap();
        assert_eq!(
            document
                .validate_worker_principal(&expected_principal)
                .unwrap_err(),
            ReceiptError::InvalidWorkerPrincipal
        );
    }
}

#[test]
fn worker_directory_receipt_rejects_duplicate_directories_secrets_and_unknown_fields() {
    let base = worker_directory_receipt_value();

    let mut duplicate = base.clone();
    duplicate["entries"][0]["directories_created"]
        .as_array_mut()
        .unwrap()
        .push(base["entries"][0]["directories_created"][0].clone());
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&duplicate).unwrap()).unwrap_err(),
        ReceiptError::ConflictingResources
    );

    let secret = "api_key=super-secret-value";
    for pointer in [
        "/entries/0/action/parameters/principal/name",
        "/entries/0/action/parameters/root",
        "/entries/0/action/parameters/path",
        "/entries/0/directories_created/0/path",
    ] {
        let mut secret_bearing = base.clone();
        *secret_bearing.pointer_mut(pointer).unwrap() = serde_json::json!(secret);
        let error =
            ReceiptDocument::from_json(&serde_json::to_vec(&secret_bearing).unwrap()).unwrap_err();
        assert!(
            !error.to_string().contains(secret),
            "secret echoed for {pointer}"
        );
    }

    for pointer in [
        "/entries/0/action/parameters",
        "/entries/0/action/parameters/principal",
        "/entries/0/action/parameters/node",
        "/entries/0/directories_created/0",
    ] {
        let mut forged = base.clone();
        forged
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".to_owned(), serde_json::json!(true));
        assert!(
            ReceiptDocument::from_json(&serde_json::to_vec(&forged).unwrap()).is_err(),
            "unknown field at {pointer} was accepted"
        );
    }
}

#[test]
fn worker_directory_pending_receipt_retains_parameters_but_requires_empty_effects() {
    let mut pending = worker_directory_receipt_value();
    pending["entries"][0]["status"] = serde_json::json!("pending");
    pending["entries"][0]["directories_created"] = serde_json::json!([]);
    ReceiptDocument::from_json(&serde_json::to_vec(&pending).unwrap()).unwrap();

    pending["entries"][0]["directories_created"] = serde_json::json!([{
        "path": pending["entries"][0]["action"]["parameters"]["path"].clone()
    }]);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&pending).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingEntry
    );
}

#[test]
fn rev_h_installation_scope_is_required_and_user_scope_is_rootless() {
    let base = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();

    let mut system = base.clone();
    system["installation_scope"] = serde_json::json!("system");
    let system = ReceiptDocument::from_json(&serde_json::to_vec(&system).unwrap()).unwrap();
    assert_eq!(system.installation_scope(), InstallationScope::System);

    let mut user = base.clone();
    user["installation_scope"] = serde_json::json!("user");
    user["entries"][0]["privilege_used"] = serde_json::json!("none");
    let user = ReceiptDocument::from_json(&serde_json::to_vec(&user).unwrap()).unwrap();
    assert_eq!(user.installation_scope(), InstallationScope::User);

    let mut missing = base.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("installation_scope");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&missing).unwrap()).unwrap_err(),
        ReceiptError::MissingInstallationScope
    );

    let mut privileged_user = base;
    privileged_user["installation_scope"] = serde_json::json!("user");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&privileged_user).unwrap()).unwrap_err(),
        ReceiptError::PrivilegeOutsideScope
    );
}

#[test]
fn checked_in_schema_example_and_canonical_serialization_stay_synchronized() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/setup-receipt-v1.schema.json"
    )))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let example_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt.json"
    ));
    let dedicated_system_example_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt-system-dedicated.json"
    ));
    let promotion_example_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt-scope-promotion.json"
    ));
    let legacy_promotion_example_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt-scope-promotion-legacy.json"
    ));
    #[cfg(not(target_os = "windows"))]
    let example = ReceiptDocument::from_json(example_bytes).unwrap();
    #[cfg(not(target_os = "windows"))]
    let dedicated_system_example =
        ReceiptDocument::from_json(dedicated_system_example_bytes).unwrap();
    #[cfg(not(target_os = "windows"))]
    let promotion_example = ReceiptDocument::from_json(promotion_example_bytes).unwrap();
    #[cfg(not(target_os = "windows"))]
    let legacy_promotion_example =
        ReceiptDocument::from_json(legacy_promotion_example_bytes).unwrap();

    let mut checkpointed = pending_receipt_value();
    checkpointed["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    let valid_values = vec![
        serde_json::from_slice::<serde_json::Value>(example_bytes).unwrap(),
        serde_json::from_slice::<serde_json::Value>(dedicated_system_example_bytes).unwrap(),
        serde_json::from_slice::<serde_json::Value>(promotion_example_bytes).unwrap(),
        serde_json::from_slice::<serde_json::Value>(legacy_promotion_example_bytes).unwrap(),
        serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap(),
        checkpointed,
    ];
    #[cfg(not(target_os = "windows"))]
    let valid_values = {
        let mut values = valid_values;
        values.push(
            serde_json::from_slice::<serde_json::Value>(&example.to_json().unwrap()).unwrap(),
        );
        values.push(
            serde_json::from_slice::<serde_json::Value>(&promotion_example.to_json().unwrap())
                .unwrap(),
        );
        assert_eq!(
            legacy_promotion_example.to_json().unwrap(),
            legacy_promotion_example_bytes
        );
        values.push(
            serde_json::from_slice::<serde_json::Value>(
                &legacy_promotion_example.to_json().unwrap(),
            )
            .unwrap(),
        );
        values.push(
            serde_json::from_slice::<serde_json::Value>(
                &dedicated_system_example.to_json().unwrap(),
            )
            .unwrap(),
        );
        values
    };
    for value in valid_values {
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "receipt schema drift: {errors:#?}");
    }

    let mut privileged_user = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    privileged_user["installation_scope"] = serde_json::json!("user");
    assert!(
        !validator.is_valid(&privileged_user),
        "schema allowed a user-scope receipt to claim privileged mutation"
    );

    let mut windows_shape = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    windows_shape["entries"][0]["files_created"][0]["path"] =
        serde_json::json!(r"C:\ProgramData\Styrn\bin\tool.exe");
    windows_shape["entries"][0]["files_modified"][0]["path"] =
        serde_json::json!(r"C:\ProgramData\Styrn\config.toml");
    windows_shape["entries"][0]["files_modified"][0]["backup_path"] =
        serde_json::json!(r"C:\ProgramData\Styrn\backups\config.toml");
    assert!(validator.is_valid(&windows_shape));

    for pointer in [
        "/entries/0",
        "/entries/0/action",
        "/entries/0/action/parameters",
        "/entries/0/files_created/0",
        "/entries/0/files_modified/0",
        "/entries/0/services/0",
        "/entries/0/accounts/0",
        "/entries/0/registry_keys/0",
        "/entries/0/firewall_rules/0",
        "/entries/0/download_provenance",
    ] {
        let mut forged = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        forged
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".to_owned(), serde_json::json!(true));
        assert!(
            !validator.is_valid(&forged),
            "schema allowed unknown field at {pointer}"
        );
    }

    for pointer in [
        "/entries/0/action/parameters",
        "/entries/0/action/parameters/principal",
        "/entries/0/action/parameters/node",
        "/entries/0/directories_created/0",
    ] {
        let mut forged = worker_directory_receipt_value();
        forged
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".to_owned(), serde_json::json!(true));
        assert!(
            !validator.is_valid(&forged),
            "schema allowed worker directory unknown field at {pointer}"
        );
    }

    let mut relative_path = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    relative_path["entries"][0]["files_created"][0]["path"] = serde_json::json!("relative/path");
    assert!(!validator.is_valid(&relative_path));

    let mut malformed_action = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    malformed_action["entries"][0]["action"]["parameters"]["action_id"] =
        serde_json::json!("test.trailing-");
    assert!(!validator.is_valid(&malformed_action));

    let mut traversal = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    traversal["entries"][0]["files_created"][0]["path"] = serde_json::json!("/opt/../tool");
    assert!(!validator.is_valid(&traversal));

    let mut hostless = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    hostless["entries"][0]["download_provenance"]["url"] = serde_json::json!("https://");
    assert!(!validator.is_valid(&hostless));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn legacy_scope_promotion_receipt_round_trips_but_is_not_established_evidence() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt-scope-promotion-legacy.json"
    ));
    let document = ReceiptDocument::from_json(bytes).unwrap();
    assert_eq!(document.to_json().unwrap(), bytes);
    assert_eq!(
        manifest_digest(bytes).0,
        "89a4859b6acc67cc0a4fd175ac9299ccc3932dca56d51f740e47526d28b71008"
    );

    let authority = crate::setup::promotion::scope_promotion_authority();
    let intent_id = uuid::Uuid::parse_str("019cad99-54a0-7000-8000-000000000042").unwrap();
    assert!(matches!(
        document.scope_promotion_checkpoint(intent_id, &authority),
        Err(ReceiptError::InvalidScopePromotion)
    ));
}

#[test]
fn scope_promotion_receipt_cannot_claim_ownership_privilege_or_selector_identity() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/setup-receipt-scope-promotion.json"
    ));
    let value = serde_json::from_slice::<serde_json::Value>(bytes).unwrap();
    ReceiptDocument::from_json(bytes).unwrap();

    let mut partial_protected = value.clone();
    partial_protected["entries"][0]["action"]["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("completion_record_identity_sha256");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&partial_protected).unwrap()).unwrap_err(),
        ReceiptError::InvalidScopePromotion
    );

    let mut system = value.clone();
    system["installation_scope"] = serde_json::json!("system");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&system).unwrap()).unwrap_err(),
        ReceiptError::InvalidScopePromotion
    );

    let mut privileged = value.clone();
    privileged["entries"][0]["privilege_used"] = serde_json::json!("root");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&privileged).unwrap()).unwrap_err(),
        ReceiptError::InvalidScopePromotion
    );

    let mut owning = value.clone();
    owning["entries"][0]["files_created"] = serde_json::json!([{
        "path": "/etc/styrn/machine.toml",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }]);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&owning).unwrap()).unwrap_err(),
        ReceiptError::InvalidScopePromotion
    );

    let mut selector_as_identity = value;
    selector_as_identity["entries"][0]["action"]["parameters"]["target_principal"]["name"] =
        serde_json::json!("release-agent");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&selector_as_identity).unwrap())
            .unwrap_err(),
        ReceiptError::InvalidScopePromotion
    );
}

#[test]
fn unknown_fields_are_rejected_at_every_receipt_object_boundary() {
    for pointer in [
        "",
        "/entries/0",
        "/entries/0/action",
        "/entries/0/action/parameters",
        "/entries/0/files_created/0",
        "/entries/0/files_modified/0",
        "/entries/0/services/0",
        "/entries/0/accounts/0",
        "/entries/0/registry_keys/0",
        "/entries/0/firewall_rules/0",
        "/entries/0/download_provenance",
    ] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".to_owned(), serde_json::Value::Bool(true));

        assert!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "unknown field at {pointer:?} must be rejected"
        );
    }

    let mut checkpointed = pending_receipt_value();
    checkpointed["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    for pointer in [
        "/pending_publications/0",
        "/pending_publications/0/pending/0",
    ] {
        let mut forged = checkpointed.clone();
        forged
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".to_owned(), serde_json::Value::Bool(true));
        assert!(ReceiptDocument::from_json(&serde_json::to_vec(&forged).unwrap()).is_err());
    }
}

#[test]
fn provenance_requires_an_https_url_with_a_real_host() {
    for url in [
        "http://downloads.example.test/tool",
        "https://:443/tool",
        "https://user@downloads.example.test/tool",
        "https://downloads.example.test\\tool",
        "https://downloads.example.test/tool#mutable-fragment",
        "https://[::::]/tool",
        "https://[2001:db8::1]oops/tool",
        "https://[2001:db8::1]:99999/tool",
        "https://downloads.example.test:/tool",
    ] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        value["entries"][0]["download_provenance"]["url"] =
            serde_json::Value::String(url.to_owned());

        assert_eq!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            ReceiptError::InvalidProvenanceUrl
        );
    }
}

#[test]
fn dynamic_resource_identifiers_must_be_nonempty() {
    for pointer in [
        "/entries/0/services/0/name",
        "/entries/0/accounts/0/name",
        "/entries/0/registry_keys/0/path",
        "/entries/0/firewall_rules/0/name",
    ] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        *value.pointer_mut(pointer).unwrap() = serde_json::json!("");
        assert_eq!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            ReceiptError::InvalidResourceIdentifier,
            "empty resource at {pointer} must be rejected"
        );
    }
}

#[test]
fn secrets_bad_digests_and_non_normalized_paths_are_rejected_without_echoing_values() {
    let secret = "api_key=super-secret-value";
    let mut cases = Vec::new();
    for pointer in [
        "/entries/0/action/parameters/action_id",
        "/entries/0/services/0/name",
        "/entries/0/download_provenance/version",
    ] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        *value.pointer_mut(pointer).unwrap() = serde_json::Value::String(secret.to_owned());
        cases.push(("secret", value, None));
    }
    for digest in ["a", &"A".repeat(64), &"g".repeat(64)] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        value["entries"][0]["files_created"][0]["sha256"] =
            serde_json::Value::String(digest.to_owned());
        cases.push(("digest", value, Some(ReceiptError::InvalidSha256)));
    }
    for path in ["relative/path", "/opt/styrn/../tool", "/opt//styrn/tool"] {
        let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
        value["entries"][0]["files_created"][0]["path"] =
            serde_json::Value::String(path.to_owned());
        cases.push(("path", value, Some(ReceiptError::InvalidRecordedPath)));
    }

    for (label, value, expected) in cases {
        let error = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        if let Some(expected) = expected {
            assert_eq!(error, expected, "unexpected {label} error");
        }
        assert!(!error.to_string().contains(secret));
    }
}

#[test]
fn conflicting_or_duplicate_effect_records_are_rejected() {
    let base = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    let mut cases = Vec::new();

    let mut duplicate_created = base.clone();
    duplicate_created["entries"][0]["files_created"]
        .as_array_mut()
        .unwrap()
        .push(base["entries"][0]["files_created"][0].clone());
    cases.push((
        "duplicate created path",
        duplicate_created,
        ReceiptError::ConflictingResources,
    ));

    let mut created_and_modified = base.clone();
    created_and_modified["entries"][0]["files_modified"][0]["path"] =
        base["entries"][0]["files_created"][0]["path"].clone();
    cases.push((
        "created and modified path",
        created_and_modified,
        ReceiptError::ConflictingResources,
    ));

    let mut backup_is_target = base.clone();
    backup_is_target["entries"][0]["files_modified"][0]["backup_path"] =
        base["entries"][0]["files_modified"][0]["path"].clone();
    cases.push((
        "backup equals target",
        backup_is_target,
        ReceiptError::ConflictingResources,
    ));

    for field in ["services", "accounts", "registry_keys", "firewall_rules"] {
        let mut duplicate = base.clone();
        let resource = duplicate["entries"][0][field][0].clone();
        duplicate["entries"][0][field]
            .as_array_mut()
            .unwrap()
            .push(resource);
        cases.push((field, duplicate, ReceiptError::ConflictingResources));
    }

    let mut wrong_registry_hive = base;
    wrong_registry_hive["entries"][0]["registry_keys"][0]["path"] =
        serde_json::Value::String(r"HKCU\Software\Styrn".to_owned());
    cases.push((
        "wrong registry hive",
        wrong_registry_hive,
        ReceiptError::InvalidResourceIdentifier,
    ));

    for (label, value, expected) in cases {
        assert_eq!(
            ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            expected,
            "{label} must be rejected"
        );
    }
}

#[test]
fn pending_entries_must_describe_no_mutation_and_no_privilege_use() {
    let pending = pending_receipt_value();
    ReceiptDocument::from_json(&serde_json::to_vec(&pending).unwrap()).unwrap();

    let mut privileged = pending.clone();
    privileged["entries"][0]["privilege_used"] = serde_json::json!("root");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&privileged).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingEntry
    );

    let mut directory_mutation = pending.clone();
    #[cfg(not(target_os = "windows"))]
    let directory_path = "/opt/styrn/jobs";
    #[cfg(target_os = "windows")]
    let directory_path = r"C:\ProgramData\Styrn\jobs";
    directory_mutation["entries"][0]["directories_created"] =
        serde_json::json!([{ "path": directory_path }]);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&directory_mutation).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingEntry
    );

    for field in [
        "files_created",
        "files_modified",
        "services",
        "accounts",
        "registry_keys",
        "firewall_rules",
        "download_provenance",
    ] {
        let mut mutated = pending.clone();
        mutated["entries"][0][field] = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT)
            .unwrap()["entries"][0][field]
            .clone();
        assert_eq!(
            ReceiptDocument::from_json(&serde_json::to_vec(&mutated).unwrap()).unwrap_err(),
            ReceiptError::InvalidPendingEntry,
            "pending entry with {field} must be rejected"
        );
    }
}

#[test]
fn pending_publications_are_optional_but_strictly_linked_append_only_epochs() {
    let legacy = ReceiptDocument::from_json(COMPLETE_RECEIPT.as_bytes()).unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&legacy.to_json().unwrap()).unwrap()
            ["pending_publications"]
            .is_null()
    );

    let mut valid = pending_receipt_value();
    valid["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    let parsed = ReceiptDocument::from_json(&serde_json::to_vec(&valid).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&parsed.to_json().unwrap()).unwrap()
            ["pending_publications"],
        valid["pending_publications"]
    );

    let mut wrong_action = valid.clone();
    wrong_action["pending_publications"][0]["pending"][0]["action_id"] =
        serde_json::json!("test.other");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&wrong_action).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingPublicationLink
    );

    let mut later_entry = valid.clone();
    later_entry["pending_publications"][0]["receipt_entry_count"] = serde_json::json!(0);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&later_entry).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingPublicationLink
    );

    let mut entry_id_collision = valid.clone();
    entry_id_collision["pending_publications"][0]["publication_id"] =
        serde_json::json!("019cafd0-5c00-7000-8000-000000000001");
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&entry_id_collision).unwrap()).unwrap_err(),
        ReceiptError::DuplicatePendingPublicationId
    );

    let mut duplicate_link = valid.clone();
    duplicate_link["pending_publications"][0]["pending"]
        .as_array_mut()
        .unwrap()
        .push(valid["pending_publications"][0]["pending"][0].clone());
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&duplicate_link).unwrap()).unwrap_err(),
        ReceiptError::DuplicatePendingPublicationLink
    );

    let mut duplicate_id = valid.clone();
    let mut second = valid["pending_publications"][0].clone();
    second["timestamp"] = serde_json::json!("2026-09-02T10:00:02Z");
    duplicate_id["pending_publications"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&duplicate_id).unwrap()).unwrap_err(),
        ReceiptError::DuplicatePendingPublicationId
    );

    let mut duplicate_timestamp = valid.clone();
    let mut second = valid["pending_publications"][0].clone();
    second["publication_id"] = serde_json::json!("019cafd0-5c00-7000-8000-000000000003");
    duplicate_timestamp["pending_publications"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&duplicate_timestamp).unwrap()).unwrap_err(),
        ReceiptError::DuplicatePendingPublicationTimestamp
    );

    let mut decreasing_count = valid.clone();
    decreasing_count["pending_publications"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "publication_id": "019cafd0-5c00-7000-8000-000000000003",
            "timestamp": "2026-09-02T10:00:02Z",
            "receipt_entry_count": 0,
            "pending": []
        }));
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&decreasing_count).unwrap()).unwrap_err(),
        ReceiptError::InvalidPendingPublicationOrder
    );

    let mut reused_resolved_entry = valid.clone();
    reused_resolved_entry["pending_publications"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!({
                "publication_id": "019cafd0-5c00-7000-8000-000000000003",
                "timestamp": "2026-09-02T10:00:02Z",
                "receipt_entry_count": 1,
                "pending": []
            }),
            serde_json::json!({
                "publication_id": "019cafd0-5c00-7000-8000-000000000004",
                "timestamp": "2026-09-02T10:00:03Z",
                "receipt_entry_count": 1,
                "pending": [{
                    "action_id": "test.first",
                    "entry_id": "019cafd0-5c00-7000-8000-000000000001"
                }]
            }),
        ]);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&reused_resolved_entry).unwrap())
            .unwrap_err(),
        ReceiptError::InvalidPendingPublicationOrder
    );

    let mut duplicate_legacy_occurrence = pending_receipt_value();
    let mut duplicate = duplicate_legacy_occurrence["entries"][0].clone();
    duplicate["entry_id"] = serde_json::json!("019cafd0-5c00-7000-8000-000000000002");
    duplicate["timestamp"] = serde_json::json!("2026-09-02T10:00:01Z");
    duplicate_legacy_occurrence["entries"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&duplicate_legacy_occurrence).unwrap())
            .unwrap_err(),
        ReceiptError::InvalidPendingPublicationOrder
    );

    let mut valid_recurrence = pending_receipt_value();
    let mut recurrence = valid_recurrence["entries"][0].clone();
    recurrence["entry_id"] = serde_json::json!("019cafd0-5c00-7000-8000-000000000003");
    recurrence["timestamp"] = serde_json::json!("2026-09-02T10:00:02Z");
    valid_recurrence["entries"]
        .as_array_mut()
        .unwrap()
        .push(recurrence);
    valid_recurrence["pending_publications"] = serde_json::json!([
        {
            "publication_id": "019cafd0-5c00-7000-8000-000000000002",
            "timestamp": "2026-09-02T10:00:01Z",
            "receipt_entry_count": 1,
            "pending": [{
                "action_id": "test.first",
                "entry_id": "019cafd0-5c00-7000-8000-000000000001"
            }]
        },
        {
            "publication_id": "019cafd0-5c00-7000-8000-000000000004",
            "timestamp": "2026-09-02T10:00:03Z",
            "receipt_entry_count": 1,
            "pending": []
        },
        {
            "publication_id": "019cafd0-5c00-7000-8000-000000000005",
            "timestamp": "2026-09-02T10:00:04Z",
            "receipt_entry_count": 2,
            "pending": [{
                "action_id": "test.first",
                "entry_id": "019cafd0-5c00-7000-8000-000000000003"
            }]
        }
    ]);
    ReceiptDocument::from_json(&serde_json::to_vec(&valid_recurrence).unwrap()).unwrap();
}

#[test]
fn pending_publication_append_cannot_modify_entry_or_checkpoint_prefixes() {
    let mut value = pending_receipt_value();
    value["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    let existing = ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let next = PendingPublication {
        publication_id: ReceiptEntryId("019cafd0-5c00-7000-8000-000000000003".to_owned()),
        timestamp: ReceiptTimestamp("2026-09-02T10:00:02Z".to_owned()),
        receipt_entry_count: 1,
        pending: Vec::new(),
    };

    let mut valid = existing.clone();
    valid.pending_publications.push(next.clone());
    validate_pending_publication_append_candidate(&existing, &valid).unwrap();

    let mut modified_entry = valid.clone();
    modified_entry.entries[0].action = ReceiptAction::Foundation(FoundationActionParameters {
        action_id: ActionIdentifier("test.changed".to_owned()),
    });
    assert!(validate_pending_publication_append_candidate(&existing, &modified_entry).is_err());

    let mut modified_checkpoint = existing.clone();
    modified_checkpoint.pending_publications[0].timestamp =
        ReceiptTimestamp("2026-09-02T10:00:03Z".to_owned());
    modified_checkpoint.pending_publications.push(next);
    assert!(matches!(
        validate_pending_publication_append_candidate(&existing, &modified_checkpoint),
        Err(ReceiptStoreError::PrefixConflict)
    ));
}

#[test]
fn append_candidate_cannot_delete_reorder_modify_or_publish_non_applied_entries() {
    let mut checkpointed = pending_receipt_value();
    checkpointed["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    let mut existing =
        ReceiptDocument::from_json(&serde_json::to_vec(&checkpointed).unwrap()).unwrap();
    existing
        .entries
        .push(entry_with_id("019cafd0-5c00-7000-8000-000000000003"));
    let third = entry_with_id("019cafd0-5c00-7000-8000-000000000004");

    let mut deleted = existing.clone();
    deleted.entries.pop();
    let mut reordered = existing.clone();
    reordered.entries.push(third.clone());
    reordered.entries.swap(1, 2);
    let mut modified = existing.clone();
    modified.entries[0].timestamp = ReceiptTimestamp("2026-09-02T10:00:08Z".to_owned());
    modified.entries.push(third.clone());
    let mut removed_checkpoint = existing.clone();
    removed_checkpoint.entries.push(third.clone());
    removed_checkpoint.pending_publications.clear();
    let mut modified_checkpoint = existing.clone();
    modified_checkpoint.entries.push(third.clone());
    modified_checkpoint.pending_publications[0].timestamp =
        ReceiptTimestamp("2026-09-02T10:00:09Z".to_owned());
    let mut non_applied = existing.clone();
    let mut pending = third;
    pending.privilege_used = ReceiptPrivilege::None;
    pending.directories_created.clear();
    pending.files_created.clear();
    pending.files_modified.clear();
    pending.services.clear();
    pending.accounts.clear();
    pending.registry_keys.clear();
    pending.firewall_rules.clear();
    pending.download_provenance = DownloadProvenanceSlot(None);
    pending.status = ReceiptStatus::Pending;
    pending.action = ReceiptAction::Foundation(FoundationActionParameters {
        action_id: ActionIdentifier("test.second".to_owned()),
    });
    non_applied.entries.push(pending);

    for candidate in [
        deleted,
        reordered,
        modified,
        removed_checkpoint,
        modified_checkpoint,
        non_applied,
    ] {
        assert!(matches!(
            validate_append_candidate(&existing, &candidate, None),
            Err(ReceiptStoreError::PrefixConflict)
        ));
    }
}

#[test]
fn pending_append_candidate_preserves_the_publication_checkpoint_prefix() {
    let mut checkpointed = pending_receipt_value();
    checkpointed["pending_publications"] = serde_json::json!([{
        "publication_id": "019cafd0-5c00-7000-8000-000000000002",
        "timestamp": "2026-09-02T10:00:01Z",
        "receipt_entry_count": 1,
        "pending": [{
            "action_id": "test.first",
            "entry_id": "019cafd0-5c00-7000-8000-000000000001"
        }]
    }]);
    let existing = ReceiptDocument::from_json(&serde_json::to_vec(&checkpointed).unwrap()).unwrap();
    let mut next_value = pending_receipt_value();
    next_value["entries"][0]["entry_id"] =
        serde_json::json!("019cafd0-5c00-7000-8000-000000000003");
    next_value["entries"][0]["timestamp"] = serde_json::json!("2026-09-02T10:00:02Z");
    next_value["entries"][0]["action"]["parameters"]["action_id"] =
        serde_json::json!("test.second");
    let next = ReceiptDocument::from_json(&serde_json::to_vec(&next_value).unwrap())
        .unwrap()
        .entries[0]
        .clone();
    let mut valid = existing.clone();
    valid.entries.push(next);
    validate_pending_append_candidate(&existing, &valid, None).unwrap();

    let mut removed = valid.clone();
    removed.pending_publications.clear();
    assert!(matches!(
        validate_pending_append_candidate(&existing, &removed, None),
        Err(ReceiptStoreError::PrefixConflict)
    ));

    let mut modified = valid;
    modified.pending_publications[0].timestamp =
        ReceiptTimestamp("2026-09-02T10:00:09Z".to_owned());
    assert!(matches!(
        validate_pending_append_candidate(&existing, &modified, None),
        Err(ReceiptStoreError::PrefixConflict)
    ));
}

#[test]
fn execution_witness_binding_compares_scope_principal_and_normalized_path() {
    let fixture = ReceiptFixture::new("execution-witness-binding");
    let principal = fixture_worker_principal();
    #[cfg(unix)]
    let other_principal = crate::platform::WorkerPrincipal::new(
        crate::platform::PrincipalKind::UnixUid,
        if principal.principal_id() == "1" {
            "2"
        } else {
            "1"
        },
        "other-worker",
        crate::platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    #[cfg(windows)]
    let other_principal = crate::platform::WorkerPrincipal::new(
        crate::platform::PrincipalKind::WindowsSid,
        "S-1-5-21-1-2-3-4242",
        "other-worker",
        crate::platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();
    let base = ReceiptExecutionWitness {
        installation_scope: InstallationScope::System,
        worker_principal: principal,
        receipt_path: normalized_path_text(fixture.receipt_path()).unwrap(),
        receipt_entry_count: 1,
        pending_publication_count: 2,
        effective_receipt_sha256: Sha256Digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ),
    };
    let reopened = base.clone();
    let mut cross_scope = base.clone();
    cross_scope.installation_scope = InstallationScope::User;
    let mut cross_principal = base.clone();
    cross_principal.worker_principal = other_principal;
    let mut cross_path = base.clone();
    cross_path.receipt_path = normalized_path_text(&fixture.root.join("other.json")).unwrap();

    assert!(base == reopened);
    assert!(base != cross_scope);
    assert!(base != cross_principal);
    assert!(base != cross_path);
}

#[test]
fn secure_store_atomically_appends_and_reads_one_complete_entry() {
    let fixture = ReceiptFixture::new("first-append");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let entry = ReceiptDocument::from_json(COMPLETE_RECEIPT.as_bytes())
        .unwrap()
        .entries[0]
        .clone();

    store.append_entry(entry.clone()).unwrap();

    let document = store.read_snapshot().unwrap();
    assert_eq!(document.entries, vec![entry]);
    assert_eq!(
        fs::read(fixture.receipt_path()).unwrap(),
        document.to_json().unwrap()
    );
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.receipt_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(
                fixture
                    .receipt_path()
                    .parent()
                    .unwrap()
                    .join(".receipt.json.lock")
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn held_verified_reader_observes_one_complete_prefix_and_does_not_block_replacement() {
    use std::io::{Read, Seek};

    let fixture = ReceiptFixture::new("held-reader");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
        .unwrap();
    let mut reader = crate::platform::open_verified_manifest_file_for_read(
        fixture.receipt_path(),
        crate::platform::ManifestOwner::CurrentProcess,
        &fixture_worker_principal(),
        fixture.receipt_path().parent().unwrap(),
    )
    .unwrap();
    let mut old_prefix = Vec::new();
    reader.read_to_end(&mut old_prefix).unwrap();

    store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000002"))
        .unwrap();

    reader.rewind().unwrap();
    let mut held_view = Vec::new();
    reader.read_to_end(&mut held_view).unwrap();
    assert_eq!(held_view, old_prefix);
    assert_eq!(
        ReceiptDocument::from_json(&held_view)
            .unwrap()
            .entries()
            .len(),
        1
    );
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 2);
}

#[test]
fn concurrent_appenders_serialize_without_lost_or_duplicate_entries() {
    let fixture = ReceiptFixture::new("concurrent-append");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let base = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    store.append_entry(base.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(8));

    std::thread::scope(|scope| {
        for sequence in 2..=9 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let id = format!("019cafd0-5c00-7000-8000-{sequence:012}");
                barrier.wait();
                store.append_entry(entry_with_id(&id)).unwrap();
            });
        }
    });

    let document = store.read_snapshot().unwrap();
    assert_eq!(document.entries.len(), 9);
    assert_eq!(document.entries[0], base);
    let ids = document
        .entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 9);
    ReceiptDocument::from_json(&fs::read(fixture.receipt_path()).unwrap()).unwrap();
}

#[test]
fn concurrent_first_use_publishers_join_the_winner_and_preserve_every_append() {
    let fixture = MissingDestinationFixture::new("concurrent-first-use");
    let receipt = fixture.receipt_path().to_path_buf();
    let barrier = Arc::new(Barrier::new(8));

    std::thread::scope(|scope| {
        for sequence in 1..=8 {
            let receipt = receipt.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let id = format!("019cafd0-5c00-7000-8000-{sequence:012}");
                barrier.wait();
                ReceiptStore::new_for_test(receipt)
                    .append_entry(entry_with_id(&id))
                    .unwrap();
            });
        }
    });

    let document = ReceiptStore::new_for_test(fixture.receipt_path())
        .read_snapshot()
        .unwrap();
    assert_eq!(document.entries().len(), 8);
    assert_eq!(
        document
            .entries()
            .iter()
            .map(|entry| entry.entry_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        8
    );
}

#[test]
fn invalid_existing_receipts_are_refused_without_rewrite() {
    let valid = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    let mut unknown_version = valid.clone();
    unknown_version["schema_version"] = serde_json::json!(2);
    let mut duplicate_id = valid.clone();
    duplicate_id["entries"]
        .as_array_mut()
        .unwrap()
        .push(valid["entries"][0].clone());
    let mut tampered_digest = valid;
    tampered_digest["entries"][0]["files_created"][0]["sha256"] =
        serde_json::Value::String("A".repeat(64));

    for (label, bytes) in [
        ("truncated", br#"{"schema_version":1,"entries":["#.to_vec()),
        (
            "unknown-version",
            serde_json::to_vec(&unknown_version).unwrap(),
        ),
        ("duplicate-id", serde_json::to_vec(&duplicate_id).unwrap()),
        (
            "tampered-digest",
            serde_json::to_vec(&tampered_digest).unwrap(),
        ),
    ] {
        let fixture = ReceiptFixture::new(label);
        let store = ReceiptStore::new_for_test(fixture.receipt_path());
        store
            .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
            .unwrap();
        fs::write(fixture.receipt_path(), &bytes).unwrap();

        let error = store
            .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000002"))
            .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert_eq!(fs::read(fixture.receipt_path()).unwrap(), bytes);
    }
}

#[test]
fn publication_interruption_leaves_only_an_old_or_one_entry_longer_valid_prefix() {
    for (label, interruption, expected_len) in [
        ("before-replace", PublicationInterruption::BeforeReplace, 1),
        ("after-replace", PublicationInterruption::AfterReplace, 2),
    ] {
        let fixture = ReceiptFixture::new(label);
        let store = ReceiptStore::new_for_test(fixture.receipt_path());
        let first = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
        store.append_entry(first.clone()).unwrap();
        let interrupted =
            ReceiptStore::new_for_test_with_interruption(fixture.receipt_path(), interruption);

        assert!(interrupted
            .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000002"))
            .is_err());

        let on_disk = ReceiptDocument::from_json(&fs::read(fixture.receipt_path()).unwrap())
            .expect("publication must never expose partial JSON");
        assert_eq!(on_disk.entries.len(), expected_len);
        assert_eq!(on_disk.entries[0], first);
    }
}

#[test]
fn recorded_windows_paths_reject_ads_embedded_drives_and_device_namespaces() {
    assert!(is_normalized_windows_path(
        r"C:\ProgramData\Styrn\receipt.json"
    ));
    for path in [
        r"C:\ProgramData\file:stream",
        r"C:\safe\D:\other",
        r"\\?\C:\ProgramData\Styrn\receipt.json",
        r"\\.\PIPE\styrn",
        r"C:\safe\file.",
        "C:\\safe\\file ",
        r"C:\safe\bad?name",
        r#"C:\safe\bad"name"#,
        r"C:\safe\COM¹.txt",
        r"C:\safe\LPT³",
    ] {
        assert!(!is_normalized_windows_path(path), "accepted {path:?}");
    }
}

#[test]
fn recorded_unix_paths_reject_traversal_duplicate_separators_and_trailing_separators() {
    assert!(is_normalized_unix_path("/opt/styrn/bin/tool"));
    for path in ["relative/path", "/opt/../tool", "/opt//tool", "/opt/tool/"] {
        assert!(!is_normalized_unix_path(path), "accepted {path:?}");
    }
}

#[test]
fn recorded_paths_must_use_the_native_platform_syntax() {
    let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    #[cfg(target_os = "windows")]
    let foreign = "/opt/styrn/bin/tool";
    #[cfg(not(target_os = "windows"))]
    let foreign = r"C:\ProgramData\Styrn\bin\tool.exe";
    value["entries"][0]["files_created"][0]["path"] = serde_json::json!(foreign);

    assert_eq!(
        ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        ReceiptError::InvalidRecordedPath
    );
}

#[test]
fn receipt_snapshot_does_not_join_the_private_writer_lock() {
    let fixture = ReceiptFixture::new("lock-free-read");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
        .unwrap();
    let lock_path = fixture
        .receipt_path()
        .parent()
        .unwrap()
        .join(".receipt.json.lock");
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    held.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();

    std::thread::scope(|scope| {
        scope.spawn(|| {
            sender.send(store.read_snapshot()).unwrap();
        });
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
                .unwrap()
                .entry_count(),
            1
        );
        drop(held);
    });
}

#[test]
fn read_with_no_receipt_or_lock_is_empty_and_does_not_create_state() {
    let fixture = ReceiptFixture::new("empty-read-no-state");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());

    assert!(store.read_snapshot().unwrap().entries().is_empty());
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn an_existing_receipt_without_its_persistent_lock_is_a_conflict_not_repaired() {
    let fixture = ReceiptFixture::new("receipt-without-lock");
    fs::write(fixture.receipt_path(), COMPLETE_RECEIPT.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(fixture.receipt_path(), fs::Permissions::from_mode(0o644)).unwrap();
    }
    let before = fs::read(fixture.receipt_path()).unwrap();

    let error = ReceiptStore::new_for_test(fixture.receipt_path())
        .read_snapshot()
        .unwrap_err();

    assert!(matches!(error, ReceiptStoreError::IntentConflict));
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), before);
    assert!(!fixture
        .receipt_path()
        .parent()
        .unwrap()
        .join(".receipt.json.lock")
        .exists());
}

#[test]
fn canonical_receipt_location_matches_the_native_platform_contract() {
    #[cfg(target_os = "linux")]
    assert_eq!(
        canonical_receipt_path(InstallationScope::System).unwrap(),
        PathBuf::from("/var/lib/styrn/receipt.json")
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        canonical_receipt_path(InstallationScope::System).unwrap(),
        PathBuf::from("/Library/Application Support/Styrn/receipt.json")
    );
    #[cfg(target_os = "windows")]
    assert_eq!(
        canonical_receipt_path(InstallationScope::System).unwrap(),
        PathBuf::from(r"C:\ProgramData\Styrn\receipt.json")
    );

    #[cfg(target_os = "linux")]
    let expected_user = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".local/state"))
        .join("styrn/receipt.json");
    #[cfg(target_os = "macos")]
    let expected_user = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join("Library/Application Support/Styrn/receipt.json");
    #[cfg(target_os = "windows")]
    let expected_user =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join(r"Styrn\receipt.json");
    assert_eq!(
        canonical_receipt_path(InstallationScope::User).unwrap(),
        expected_user
    );
}

#[test]
fn canonical_store_requires_an_explicit_valid_worker_principal() {
    for name in ["", "worker\0name", "worker\nname"] {
        assert!(crate::platform::WorkerPrincipal::new(
            crate::platform::PrincipalKind::UnixUid,
            "501",
            name,
            crate::platform::WorkerAccountPolicy::CurrentUser,
        )
        .is_err());
    }

    let principal = fixture_worker_principal();
    let store = configured_system_receipt_store(principal.clone()).unwrap();
    assert_eq!(store.worker, principal);
    assert_eq!(store.scope, InstallationScope::System);

    let user = configured_receipt_store().unwrap();
    assert_eq!(user.worker, fixture_worker_principal());
    assert_eq!(user.scope, InstallationScope::User);
}

#[test]
fn user_store_rejects_a_different_principal_before_filesystem_mutation() {
    let fixture = MissingDestinationFixture::new("different-user-principal");
    let current = fixture_worker_principal();
    let different_name = if current.name() == "mismatched-native-name" {
        "another-mismatched-native-name"
    } else {
        "mismatched-native-name"
    };
    let different = crate::platform::WorkerPrincipal::new(
        current.principal_kind(),
        current.principal_id(),
        different_name,
        crate::platform::WorkerAccountPolicy::CurrentUser,
    )
    .unwrap();

    let error = ReceiptStore::new_user(fixture.receipt_path(), different).unwrap_err();

    assert!(matches!(error, ReceiptStoreError::InvalidPrincipal(_)));
    assert!(!fixture.receipt_path().parent().unwrap().exists());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
}

#[test]
fn ordinary_user_scope_creates_a_restricted_rootless_journal() {
    let fixture = MissingDestinationFixture::new("user-scope");
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    let mut entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    entry.privilege_used = ReceiptPrivilege::None;

    store.append_entry(entry).unwrap();

    let snapshot = store.read_snapshot().unwrap();
    assert_eq!(snapshot.installation_scope(), InstallationScope::User);
    assert_eq!(snapshot.entry_count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.receipt_path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [
            fixture.receipt_path().to_path_buf(),
            fixture
                .receipt_path()
                .parent()
                .unwrap()
                .join(".receipt.json.lock"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn user_scope_creates_a_missing_standard_state_root_from_a_secure_user_anchor() {
    let fixture = MissingDestinationFixture::new("missing-user-state-root");
    let receipt = fixture
        .root
        .join("state")
        .join("styrn")
        .join("receipt.json");
    let store = ReceiptStore::new_user_for_test(&receipt);
    let mut entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    entry.privilege_used = ReceiptPrivilege::None;

    store.append_entry(entry).unwrap();

    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [fixture.root.join("state"), fixture.root.join("state/styrn")] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn user_scope_rejects_cross_user_writable_trusted_state_root_without_partial_state() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = MissingDestinationFixture::new("user-insecure-state-root");
    let trusted_root = fixture.receipt_path().parent().unwrap().parent().unwrap();
    fs::set_permissions(trusted_root, fs::Permissions::from_mode(0o777)).unwrap();
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    let mut entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    entry.privilege_used = ReceiptPrivilege::None;

    let error = store.append_entry(entry).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert!(!fixture.receipt_path().parent().unwrap().exists());
    assert_eq!(
        fs::metadata(trusted_root).unwrap().permissions().mode() & 0o777,
        0o777
    );
}

#[cfg(unix)]
#[test]
fn user_scope_rejects_secure_trusted_root_beneath_non_sticky_writable_parent() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = MissingDestinationFixture::new("user-insecure-state-parent");
    let insecure_parent = fixture.root.join("cross-principal-parent");
    let trusted_root = insecure_parent.join("state");
    fs::create_dir_all(&trusted_root).unwrap();
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&trusted_root, fs::Permissions::from_mode(0o700)).unwrap();
    let receipt = trusted_root.join("styrn/receipt.json");
    let store = ReceiptStore::new_user_for_test(&receipt);
    let mut entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    entry.privilege_used = ReceiptPrivilege::None;

    let error = store.append_entry(entry).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert!(!trusted_root.join("styrn").exists());
    assert_eq!(
        fs::metadata(&insecure_parent).unwrap().permissions().mode() & 0o777,
        0o777
    );
    assert_eq!(
        fs::metadata(&trusted_root).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[cfg(unix)]
#[test]
fn user_scope_accepts_secure_trusted_root_beneath_sticky_shared_parent() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = MissingDestinationFixture::new("user-sticky-state-parent");
    let sticky_parent = fixture.root.join("sticky-parent");
    let trusted_root = sticky_parent.join("state");
    fs::create_dir_all(&trusted_root).unwrap();
    fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1777)).unwrap();
    fs::set_permissions(&trusted_root, fs::Permissions::from_mode(0o700)).unwrap();
    let receipt = trusted_root.join("styrn/receipt.json");
    let store = ReceiptStore::new_user_for_test(&receipt);
    let mut entry = entry_with_id("019cafd0-5c00-7000-8000-000000000001");
    entry.privilege_used = ReceiptPrivilege::None;

    store.append_entry(entry).unwrap();

    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn selected_store_scope_rejects_a_document_from_the_other_scope_without_rewrite() {
    let fixture = MissingDestinationFixture::new("scope-mismatch");
    fs::create_dir_all(fixture.receipt_path().parent().unwrap()).unwrap();
    crate::platform::harden_manifest_directory(
        fixture.receipt_path().parent().unwrap(),
        crate::platform::ManifestOwner::User,
        &fixture_worker_principal(),
    )
    .unwrap();
    let bytes = COMPLETE_RECEIPT.as_bytes();
    fs::write(fixture.receipt_path(), bytes).unwrap();
    crate::platform::harden_manifest_file(
        fixture.receipt_path(),
        crate::platform::ManifestOwner::User,
        &fixture_worker_principal(),
    )
    .unwrap();
    let lock = fixture
        .receipt_path()
        .parent()
        .unwrap()
        .join(".receipt.json.lock");
    drop(
        crate::platform::create_private_file(
            &lock,
            crate::platform::ManifestOwner::User,
            &fixture_worker_principal(),
        )
        .unwrap(),
    );
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());

    let error = store.read_snapshot().unwrap_err();

    assert!(matches!(error, ReceiptStoreError::ScopeMismatch));
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), bytes);
}

#[test]
fn test_destination_override_rejects_relative_non_normalized_and_wrong_leaf_paths() {
    let fixture = ReceiptFixture::new("invalid-destination-policy");
    let paths = [
        PathBuf::from("relative/receipt.json"),
        fixture
            .receipt_path()
            .parent()
            .unwrap()
            .join("child")
            .join("..")
            .join("receipt.json"),
        fixture.receipt_path().with_file_name("journal.json"),
    ];

    for path in paths {
        let existed = path.exists();
        let error = ReceiptStore::new_for_test(&path)
            .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
            .unwrap_err();
        assert!(matches!(error, ReceiptStoreError::InvalidDestination));
        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert_eq!(
            path.exists(),
            existed,
            "invalid override created partial state"
        );
    }
}

#[cfg(unix)]
#[test]
fn receipt_targets_reject_symlinks_fifos_and_directories_without_rewrite() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    for kind in ["symlink", "fifo", "directory"] {
        let fixture = ReceiptFixture::new(&format!("receipt-target-{kind}"));
        let path = fixture.receipt_path();
        let outside = fixture.root.join("outside");
        match kind {
            "symlink" => {
                fs::write(&outside, b"outside must remain unchanged").unwrap();
                symlink(&outside, path).unwrap();
            }
            "fifo" => {
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "directory" => fs::create_dir(path).unwrap(),
            _ => unreachable!(),
        }

        let error = ReceiptStore::new_for_test(path)
            .read_snapshot()
            .unwrap_err();

        assert!(matches!(error, ReceiptStoreError::Security(_)));
        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            !name.contains(".receipt.json.lock")
                && !name.contains(".tmp")
                && !name.contains("transaction")
        }));
        if kind == "symlink" {
            assert_eq!(fs::read(outside).unwrap(), b"outside must remain unchanged");
        }
    }
}

#[cfg(unix)]
#[test]
fn receipt_locks_reject_symlinks_fifos_directories_and_insecure_modes() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink, fs::PermissionsExt};

    for kind in ["symlink", "fifo", "directory", "insecure-mode"] {
        let fixture = ReceiptFixture::new(&format!("receipt-lock-{kind}"));
        let lock_path = fixture
            .receipt_path()
            .parent()
            .unwrap()
            .join(".receipt.json.lock");
        let outside = fixture.root.join("outside-lock");
        match kind {
            "symlink" => {
                fs::write(&outside, b"outside lock must remain unchanged").unwrap();
                symlink(&outside, &lock_path).unwrap();
            }
            "fifo" => {
                let path = std::ffi::CString::new(lock_path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "directory" => fs::create_dir(&lock_path).unwrap(),
            "insecure-mode" => {
                fs::write(&lock_path, []).unwrap();
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o666)).unwrap();
            }
            _ => unreachable!(),
        }

        let error = ReceiptStore::new_for_test(fixture.receipt_path())
            .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
            .unwrap_err();

        assert!(matches!(error, ReceiptStoreError::Write(_)));
        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert!(!fixture.receipt_path().exists());
        if kind == "symlink" {
            assert_eq!(
                fs::read(outside).unwrap(),
                b"outside lock must remain unchanged"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn insecure_or_worker_owned_destination_chains_are_rejected_before_publication() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = ReceiptFixture::new("insecure-directory");
    fs::set_permissions(
        fixture.receipt_path().parent().unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let error = store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
        .unwrap_err();
    assert!(matches!(error, ReceiptStoreError::Security(_)));
    assert!(!fixture.receipt_path().exists());

    let worker_fixture = ReceiptFixture::new("worker-owned-parent");
    let destination = worker_fixture.root.join("worker-parent").join("styrn");
    fs::create_dir(worker_fixture.root.join("worker-parent")).unwrap();
    let receipt = destination.join("receipt.json");
    let mut worker_store = ReceiptStore::new_for_test(&receipt);
    worker_store.owner = crate::platform::ManifestOwner::CurrentProcessWorker;
    let error = worker_store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
        .unwrap_err();
    assert!(matches!(error, ReceiptStoreError::Security(_)));
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
#[ignore = "environmental: root plus STYRN_UNIX_TEST_WORKER selecting a real unprivileged account"]
fn real_selected_worker_can_read_but_cannot_mutate_replace_or_take_over_receipt() {
    use std::ffi::CString;
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    use std::process::ExitStatus;

    assert_eq!(unsafe { libc::geteuid() }, 0, "requires root privileges");
    let worker = std::env::var("STYRN_UNIX_TEST_WORKER")
        .expect("STYRN_UNIX_TEST_WORKER must select a real unprivileged account");
    let account = CString::new(worker.as_str()).unwrap();
    let password = unsafe { libc::getpwnam(account.as_ptr()) };
    assert!(!password.is_null(), "selected worker account must exist");
    let uid = unsafe { (*password).pw_uid };
    let gid = unsafe { (*password).pw_gid };
    assert_ne!(uid, 0, "selected worker must be an unprivileged account");

    let nonce = Uuid::now_v7();
    #[cfg(target_os = "linux")]
    let directory = PathBuf::from(format!("/var/lib/styrn-receipt-test-{nonce}"));
    #[cfg(target_os = "macos")]
    let directory = PathBuf::from(format!(
        "/Library/Application Support/Styrn Receipt Test {nonce}"
    ));
    let receipt = directory.join("receipt.json");
    let principal = crate::platform::resolve_named_worker_principal(
        &worker,
        crate::platform::WorkerAccountPolicy::Dedicated,
    )
    .unwrap();
    let store = ReceiptStore::new_system(&receipt, principal.clone()).unwrap();
    store
        .append_entry(entry_with_id("019cafd0-5c00-7000-8000-000000000001"))
        .unwrap();
    let replacement_directory = directory
        .parent()
        .unwrap()
        .join(format!("styrn-receipt-worker-replacement-{nonce}"));
    fs::create_dir(&replacement_directory).unwrap();
    std::os::unix::fs::chown(&replacement_directory, Some(uid), Some(gid)).unwrap();
    fs::set_permissions(&replacement_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = replacement_directory.join("replacement.json");
    let private_intent = directory.join(".receipt.json.transaction.permission-test.json");
    drop(
        crate::platform::create_private_file(
            &private_intent,
            crate::platform::ManifestOwner::System,
            &principal,
        )
        .unwrap(),
    );

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        #[cfg(target_os = "linux")]
        let group_ok = unsafe { libc::initgroups(account.as_ptr(), gid) } == 0;
        #[cfg(target_os = "macos")]
        let group_ok = unsafe {
            libc::initgroups(
                account.as_ptr(),
                libc::c_int::try_from(gid).expect("configured worker gid must fit c_int"),
            )
        } == 0;
        let gid_ok = unsafe { libc::setgid(gid) } == 0;
        let uid_ok = unsafe { libc::setuid(uid) } == 0;
        let readable = store.read_snapshot().is_ok();
        let lock_denied = fs::File::open(directory.join(".receipt.json.lock"))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let intent_denied = fs::File::open(&private_intent)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let write_denied = fs::OpenOptions::new()
            .write(true)
            .open(&receipt)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let delete_denied = fs::remove_file(&receipt)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let rename_denied = fs::rename(&receipt, directory.join("stolen.json"))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let replacement_created = fs::write(&replacement, b"replacement").is_ok();
        let replace_denied = fs::rename(&replacement, &receipt)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let chmod_denied = fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        let chown_denied = std::os::unix::fs::chown(&receipt, Some(uid), Some(gid))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe {
            libc::_exit(i32::from(
                !(group_ok
                    && gid_ok
                    && uid_ok
                    && readable
                    && lock_denied
                    && intent_denied
                    && write_denied
                    && delete_denied
                    && rename_denied
                    && replacement_created
                    && replace_denied
                    && chmod_denied
                    && chown_denied),
            ));
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    let status = ExitStatus::from_raw(status);
    let _ = fs::remove_file(&replacement);
    let _ = fs::remove_dir(&replacement_directory);
    let _ = fs::remove_file(&private_intent);
    let _ = fs::remove_file(&receipt);
    let _ = fs::remove_file(directory.join(".receipt.json.lock"));
    let _ = fs::remove_dir(&directory);
    assert!(status.success());
}

fn entry_with_id(id: &str) -> ReceiptEntry {
    let mut value = serde_json::from_str::<serde_json::Value>(COMPLETE_RECEIPT).unwrap();
    value["entries"][0]["entry_id"] = serde_json::Value::String(id.to_owned());
    ReceiptDocument::from_json(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .entries[0]
        .clone()
}

struct ReceiptFixture {
    root: PathBuf,
    receipt: PathBuf,
}

impl ReceiptFixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "styrn-receipt-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let directory = root.join("styrn");
        fs::create_dir_all(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let receipt = directory.join("receipt.json");
        Self { root, receipt }
    }

    fn receipt_path(&self) -> &std::path::Path {
        &self.receipt
    }
}

impl Drop for ReceiptFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct MissingDestinationFixture {
    root: PathBuf,
    receipt: PathBuf,
}

impl MissingDestinationFixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-receipt-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        let receipt = root.join("styrn").join("receipt.json");
        Self { root, receipt }
    }

    fn receipt_path(&self) -> &Path {
        &self.receipt
    }
}

impl Drop for MissingDestinationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
