fn section<'a>(document: &'a str, start: &str, end: &str) -> &'a str {
    let start = document
        .find(start)
        .unwrap_or_else(|| panic!("missing section start {start}"));
    let remainder = &document[start..];
    let end = remainder
        .find(end)
        .unwrap_or_else(|| panic!("missing section end {end}"));
    &remainder[..end]
}

fn assert_contains_all(section: &str, required: &[&str]) {
    for value in required {
        assert!(section.contains(value), "missing {value}");
    }
}

#[test]
fn canonical_design_owns_linux_host_profiles_once() {
    let design = include_str!("../docs/design.md");
    let plan = include_str!("../docs/implementation-plan.md");
    let phase = section(design, "## 16.3", "## 16.5");
    let t0_8 = section(plan, "**T0.8**", "**T0.9**");

    assert_eq!(
        phase
            .matches("Linux host profile, WSL refusal, and package-backend adaptation")
            .count(),
        1
    );
    assert_contains_all(
        phase,
        &[
            "Debian, Red Hat, and Arch",
            "apt-get",
            "dnf5",
            "pacman",
            "setup.unsupported_os",
        ],
    );
    assert_contains_all(
        t0_8,
        &[
            "distribution, package, system-service, and user-service",
            "degrade independently",
            "only kernel disposition",
        ],
    );
}

#[test]
fn supporting_spec_closes_linux_detection_and_package_contracts() {
    let spec = include_str!("../docs/superpowers/specs/2026-09-04-linux-host-profile-design.md");
    let package_actions = section(spec, "## Package actions", "## Probe and planning behavior");
    let planning = section(spec, "## Probe and planning behavior", "## Test strategy");

    assert!(!spec.contains("pending review"));
    assert!(!spec.contains("Part 7.10"));
    assert_contains_all(
        package_actions,
        &[
            "openssh-server",
            "openssh",
            "cockpit",
            "Tailscale",
            "unsupported",
            "dpkg-query",
            "list --installed",
            "pacman -Q",
        ],
    );
    assert_contains_all(
        planning,
        &[
            "LinuxExecutableIdentity",
            "request digest",
            "expected effect",
            "non-cloneable",
            "non-serializable",
        ],
    );
}

#[test]
fn phase_zero_plan_tracks_receipts_and_linux_account_policy_separately() {
    let plan = include_str!("../docs/implementation-plan.md");
    let t0_11 = section(plan, "**T0.11**", "**T0.12**");
    let t0_14 = section(plan, "**T0.14**", "**T0.15**");

    assert_contains_all(
        t0_11,
        &[
            "backend",
            "executable identity",
            "component",
            "package identifier",
            "scope",
            "finalized effect",
        ],
    );
    assert_contains_all(
        t0_14,
        &[
            "non-root",
            "non-service",
            "non-admin",
            "usable shell",
            "unique secure home",
            "NSS",
            "sudo origin",
        ],
    );
}

#[test]
fn test_plan_keeps_container_and_native_service_evidence_distinct() {
    let design = include_str!("../docs/design.md");
    let plan = include_str!("../docs/implementation-plan.md");
    let strategy = section(design, "## 16.6", "## 16.7");
    let c5 = section(plan, "**C5**", "**C6**");
    let c8 = section(plan, "**C8**", "**C9**");

    assert_contains_all(
        strategy,
        &[
            "ARM64",
            "container",
            "do not certify service lifecycle",
            "real systemd VM/host",
            "WSL",
        ],
    );
    assert_contains_all(c5, &["WSL", "setup.unsupported_os"]);
    assert_contains_all(
        c8,
        &[
            "Omarchy ARM64",
            "user-manager/linger",
            "service lifecycle",
            "unavailable until run",
        ],
    );
}
