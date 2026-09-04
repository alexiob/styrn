use serde::Deserialize;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const COMPONENTS: [Component; 12] = [
    Component::SshServer,
    Component::Tailscale,
    Component::Git,
    Component::Rust,
    Component::Sccache,
    Component::Herdr,
    Component::Codex,
    Component::Claude,
    Component::Styrnd,
    Component::SleepPolicy,
    Component::Rdp,
    Component::Cockpit,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Component {
    SshServer,
    Tailscale,
    Git,
    Rust,
    Sccache,
    Herdr,
    Codex,
    Claude,
    Styrnd,
    SleepPolicy,
    Rdp,
    Cockpit,
}
impl Component {
    const fn name(self) -> &'static str {
        match self {
            Self::SshServer => "ssh-server",
            Self::Tailscale => "tailscale",
            Self::Git => "git",
            Self::Rust => "rust",
            Self::Sccache => "sccache",
            Self::Herdr => "herdr",
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Styrnd => "styrnd",
            Self::SleepPolicy => "sleep-policy",
            Self::Rdp => "rdp",
            Self::Cockpit => "cockpit",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        COMPONENTS.into_iter().find(|item| item.name() == value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::setup) struct EffectiveRootlessSetup {
    role: String,
    scope: crate::platform::InstallationScope,
    account_mode: String,
    account_name: Option<String>,
    name: Option<String>,
    components: Vec<Component>,
    root: String,
    authorized_keys: Vec<String>,
    tailscale_mode: String,
    tailscale_auth_key_env: String,
    fail_on_pending: bool,
}
impl EffectiveRootlessSetup {
    pub(in crate::setup) fn machine_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub(in crate::setup) const fn fail_on_pending(&self) -> bool {
        self.fail_on_pending
    }

    pub(in crate::setup) fn selected_component_names(
        &self,
    ) -> impl ExactSizeIterator<Item = &'static str> + '_ {
        self.components.iter().map(|component| component.name())
    }

    pub(in crate::setup) fn authorized_public_keys(&self) -> &[String] {
        &self.authorized_keys
    }

    pub(in crate::setup) fn requested_tailscale_mode(&self) -> &str {
        &self.tailscale_mode
    }

    #[cfg(test)]
    fn component_names(&self) -> Vec<&'static str> {
        self.selected_component_names().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::setup) enum SetupInputError {
    Usage(String),
    Config(String),
    Plan(String),
}
impl fmt::Display for SetupInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) | Self::Config(message) | Self::Plan(message) => {
                f.write_str(message)
            }
        }
    }
}
impl std::error::Error for SetupInputError {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupConfigV1 {
    schema_version: Option<u8>,
    role: Option<String>,
    name: Option<String>,
    installation: Option<InstallationConfig>,
    components: Option<ComponentsConfig>,
    account: Option<AccountConfig>,
    dirs: Option<DirsConfig>,
    ssh: Option<SshConfig>,
    tailscale: Option<TailscaleConfig>,
    pending_policy: Option<PendingPolicyConfig>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationConfig {
    scope: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentsConfig {
    #[serde(rename = "ssh-server")]
    ssh_server: Option<bool>,
    tailscale: Option<bool>,
    git: Option<bool>,
    rust: Option<bool>,
    sccache: Option<bool>,
    herdr: Option<bool>,
    codex: Option<bool>,
    claude: Option<bool>,
    styrnd: Option<bool>,
    #[serde(rename = "sleep-policy")]
    sleep_policy: Option<bool>,
    rdp: Option<bool>,
    cockpit: Option<bool>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountConfig {
    mode: Option<String>,
    name: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirsConfig {
    root: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshConfig {
    authorized_keys: Option<Vec<String>>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TailscaleConfig {
    mode: Option<String>,
    auth_key_env: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingPolicyConfig {
    fail_on_pending: Option<bool>,
}

pub(in crate::setup) fn load_effective_rootless_setup(
    request: &crate::cli::SetupRequest,
) -> Result<EffectiveRootlessSetup, SetupInputError> {
    let config = request
        .config()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();
    let role = request
        .role()
        .map(str::to_owned)
        .or(config.role)
        .unwrap_or_else(|| "worker".into());
    let scope = match request.scope() {
        Some(scope) => scope,
        None => match config
            .installation
            .as_ref()
            .and_then(|value| value.scope.as_deref())
        {
            Some(value) => parse_scope(value)?,
            None => crate::platform::InstallationScope::User,
        },
    };
    let account = match request.account() {
        Some(value) => parse_account(value)?,
        None => config
            .account
            .as_ref()
            .map(|value| {
                (
                    value.mode.clone().unwrap_or_else(|| "current-user".into()),
                    value.name.clone(),
                )
            })
            .unwrap_or_else(|| ("current-user".into(), None)),
    };
    let mut selected = default_components();
    if let Some(components) = config.components.as_ref() {
        apply_component_config(&mut selected, components);
    }
    if let Some(install) = request.install() {
        for component in parse_install(install)? {
            set_component(&mut selected, component, true);
        }
    }
    let effective = EffectiveRootlessSetup {
        role,
        scope,
        account_mode: account.0,
        account_name: account.1,
        name: request.name().map(str::to_owned).or(config.name),
        components: COMPONENTS
            .into_iter()
            .filter(|component| selected.contains(component))
            .collect(),
        root: config
            .dirs
            .as_ref()
            .and_then(|value| value.root.clone())
            .unwrap_or_default(),
        authorized_keys: config
            .ssh
            .as_ref()
            .and_then(|value| value.authorized_keys.clone())
            .unwrap_or_default(),
        tailscale_mode: config
            .tailscale
            .as_ref()
            .and_then(|value| value.mode.clone())
            .unwrap_or_default(),
        tailscale_auth_key_env: config
            .tailscale
            .as_ref()
            .and_then(|value| value.auth_key_env.clone())
            .unwrap_or_else(|| "TS_AUTHKEY".into()),
        fail_on_pending: config
            .pending_policy
            .as_ref()
            .and_then(|value| value.fail_on_pending)
            .unwrap_or(false),
    };
    validate_effective(&effective, request)?;
    Ok(effective)
}

fn read_config(path: &Path) -> Result<SetupConfigV1, SetupInputError> {
    let initial =
        fs::symlink_metadata(path).map_err(|_| config_error("config input is unavailable"))?;
    if !initial.file_type().is_file() && !initial.file_type().is_symlink() {
        return Err(config_error("config input must be a regular file"));
    }
    let mut file = File::open(path).map_err(|_| config_error("config input is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| config_error("config input is unavailable"))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(config_error(
            "config input must be a regular file smaller than 1 MiB",
        ));
    }
    let mut input = String::new();
    file.read_to_string(&mut input)
        .map_err(|_| config_error("config input is not valid UTF-8"))?;
    if input.len() > MAX_CONFIG_BYTES as usize {
        return Err(config_error(
            "config input must be a regular file smaller than 1 MiB",
        ));
    }
    let config: SetupConfigV1 =
        toml::from_str(&input).map_err(|error| toml_error(&input, error))?;
    if config.schema_version != Some(1) {
        return Err(config_error("config key schema_version must be 1"));
    }
    validate_config_enums(&config)?;
    Ok(config)
}

fn validate_config_enums(config: &SetupConfigV1) -> Result<(), SetupInputError> {
    if config
        .role
        .as_deref()
        .is_some_and(|role| !matches!(role, "controller" | "worker" | "both"))
    {
        return Err(config_error("config key role is invalid"));
    }
    if config
        .account
        .as_ref()
        .and_then(|account| account.mode.as_deref())
        .is_some_and(|mode| !matches!(mode, "current-user" | "dedicated"))
    {
        return Err(config_error("config key account.mode is invalid"));
    }
    if config
        .tailscale
        .as_ref()
        .and_then(|tailscale| tailscale.mode.as_deref())
        .is_some_and(|mode| !matches!(mode, "" | "tailscaled"))
    {
        return Err(config_error("config key tailscale.mode is invalid"));
    }
    Ok(())
}
fn parse_scope(value: &str) -> Result<crate::platform::InstallationScope, SetupInputError> {
    match value {
        "user" => Ok(crate::platform::InstallationScope::User),
        "system" => Ok(crate::platform::InstallationScope::System),
        _ => Err(config_error("config key installation.scope is invalid")),
    }
}
fn parse_account(value: &str) -> Result<(String, Option<String>), SetupInputError> {
    if value == "current-user" {
        return Ok((value.into(), None));
    }
    if value == "dedicated" {
        return Ok((value.into(), None));
    }
    if let Some(name) = value.strip_prefix("dedicated:") {
        return if name.is_empty() {
            Err(usage_error("--account dedicated requires a name"))
        } else {
            Ok(("dedicated".into(), Some(name.into())))
        };
    }
    Err(usage_error(
        "--account must be current-user or dedicated[:NAME]",
    ))
}
fn default_components() -> Vec<Component> {
    vec![
        Component::SshServer,
        Component::Tailscale,
        Component::Git,
        Component::Styrnd,
        Component::SleepPolicy,
    ]
}
fn set_component(selected: &mut Vec<Component>, component: Component, enabled: bool) {
    selected.retain(|current| *current != component);
    if enabled {
        selected.push(component);
    }
}
fn apply_component_config(selected: &mut Vec<Component>, config: &ComponentsConfig) {
    for (component, enabled) in [
        (Component::SshServer, config.ssh_server),
        (Component::Tailscale, config.tailscale),
        (Component::Git, config.git),
        (Component::Rust, config.rust),
        (Component::Sccache, config.sccache),
        (Component::Herdr, config.herdr),
        (Component::Codex, config.codex),
        (Component::Claude, config.claude),
        (Component::Styrnd, config.styrnd),
        (Component::SleepPolicy, config.sleep_policy),
        (Component::Rdp, config.rdp),
        (Component::Cockpit, config.cockpit),
    ] {
        if let Some(enabled) = enabled {
            set_component(selected, component, enabled);
        }
    }
}
fn parse_install(input: &str) -> Result<Vec<Component>, SetupInputError> {
    let mut output = Vec::new();
    for item in input.split(',') {
        let item = item.trim_matches(|value: char| value.is_ascii_whitespace());
        if item.is_empty() {
            return Err(usage_error("--install contains an empty component; valid components: ssh-server, tailscale, git, rust, sccache, herdr, codex, claude, styrnd, sleep-policy, rdp, cockpit"));
        }
        let item = if item == "ssh" { "ssh-server" } else { item };
        let Some(component) = Component::parse(item) else {
            return Err(usage_error("--install names an unknown component; valid components: ssh-server, tailscale, git, rust, sccache, herdr, codex, claude, styrnd, sleep-policy, rdp, cockpit"));
        };
        if !output.contains(&component) {
            output.push(component);
        }
    }
    Ok(output)
}
pub(in crate::setup) fn effective_from_interactive_answers(
    role: String,
    components: Option<&str>,
    name: Option<String>,
) -> Result<EffectiveRootlessSetup, SetupInputError> {
    let mut selected = default_components();
    if let Some(components) = components {
        for component in parse_install(components)? {
            set_component(&mut selected, component, true);
        }
    }
    let effective = EffectiveRootlessSetup {
        role,
        scope: crate::platform::InstallationScope::User,
        account_mode: "current-user".into(),
        account_name: None,
        name,
        components: COMPONENTS
            .into_iter()
            .filter(|component| selected.contains(component))
            .collect(),
        root: String::new(),
        authorized_keys: Vec::new(),
        tailscale_mode: String::new(),
        tailscale_auth_key_env: "TS_AUTHKEY".into(),
        fail_on_pending: false,
    };
    validate_interactive_effective(&effective)?;
    Ok(effective)
}
fn validate_interactive_effective(
    effective: &EffectiveRootlessSetup,
) -> Result<(), SetupInputError> {
    if effective.role != "worker" {
        return Err(SetupInputError::Plan(
            "rootless setup supports only role=worker".into(),
        ));
    }
    validate_name(effective.name.as_deref())
}
fn validate_effective(
    effective: &EffectiveRootlessSetup,
    request: &crate::cli::SetupRequest,
) -> Result<(), SetupInputError> {
    if effective.role != "worker"
        || effective.scope != crate::platform::InstallationScope::User
        || effective.account_mode != "current-user"
        || effective.account_name.is_some()
        || !effective.root.is_empty()
        || request.authorize_system()
        || request.emit_script().is_some()
        || request.uninstall()
    {
        return Err(SetupInputError::Plan("rootless setup supports only scope=user role=worker account=current-user with canonical paths and no mutation flags".into()));
    }
    if !matches!(effective.tailscale_mode.as_str(), "" | "tailscaled")
        || !valid_env_name(&effective.tailscale_auth_key_env)
    {
        return Err(config_error("config key tailscale is invalid"));
    }
    validate_name(effective.name.as_deref())?;
    let mut keys = std::collections::BTreeSet::new();
    for key in &effective.authorized_keys {
        if !valid_public_key(key) || !keys.insert(key) {
            return Err(config_error("config key ssh.authorized_keys is invalid"));
        }
    }
    Ok(())
}
fn valid_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}
fn validate_name(value: Option<&str>) -> Result<(), SetupInputError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty()
        || value.len() > 63
        || value.bytes().any(|byte| byte.is_ascii_control())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(SetupInputError::Plan(
            "machine name is not safe static manifest text".into(),
        ));
    }
    Ok(())
}
fn valid_public_key(value: &str) -> bool {
    if value.bytes().any(|byte| byte.is_ascii_control()) || value.contains("PRIVATE KEY") {
        return false;
    }
    let mut parts = value.split_ascii_whitespace();
    let (Some(kind), Some(encoded)) = (parts.next(), parts.next()) else {
        return false;
    };
    parts
        .next()
        .is_none_or(|comment| !comment.contains("PRIVATE KEY"))
        && matches!(
            kind,
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        )
        && base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .is_ok_and(|bytes| !bytes.is_empty())
}
fn usage_error(message: &str) -> SetupInputError {
    SetupInputError::Usage(message.into())
}
fn config_error(message: &str) -> SetupInputError {
    SetupInputError::Config(message.into())
}
fn toml_error(input: &str, error: toml::de::Error) -> SetupInputError {
    let offset = error.span().map_or(0, |span| span.start.min(input.len()));
    let line = input[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = offset
        - input[..offset]
            .rfind('\n')
            .map_or(0, |position| position + 1)
        + 1;
    let key = dotted_key_at(input, line).unwrap_or_else(|| "config".into());
    SetupInputError::Config(format!(
        "config key {key} is invalid at line {line}, column {column}"
    ))
}
fn dotted_key_at(input: &str, line_number: usize) -> Option<String> {
    let mut table = String::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            let candidate = &line[1..line.len() - 1];
            if candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                table = candidate.into();
            }
        }
        if index + 1 == line_number {
            let key = line
                .split_once('=')
                .map(|(key, _)| key.trim())
                .filter(|key| !key.is_empty())?;
            if !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return None;
            }
            return Some(if table.is_empty() {
                key.into()
            } else {
                format!("{table}.{key}")
            });
        }
    }
    None
}

pub(in crate::setup) fn replay_toml(effective: &EffectiveRootlessSetup) -> String {
    let mut output = String::from("schema_version = 1\n");
    output.push_str(&format!("role = {:?}\n", effective.role));
    if let Some(name) = &effective.name {
        output.push_str(&format!("name = {:?}\n", name));
    }
    output.push_str("\n[installation]\nscope = \"user\"\n\n[components]\n");
    for component in COMPONENTS {
        output.push_str(&format!(
            "{} = {}\n",
            component.name(),
            effective.components.contains(&component)
        ));
    }
    output.push_str(
        "\n[account]\nmode = \"current-user\"\n\n[dirs]\nroot = \"\"\n\n[ssh]\nauthorized_keys = [",
    );
    for (index, key) in effective.authorized_keys.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        output.push_str(&format!("{:?}", key));
    }
    output.push_str("]\n\n[tailscale]\n");
    output.push_str(&format!(
        "mode = {:?}\nauth_key_env = {:?}\n\n[pending_policy]\nfail_on_pending = {}\n",
        effective.tailscale_mode, effective.tailscale_auth_key_env, effective.fail_on_pending
    ));
    output
}
pub(in crate::setup) fn persist_interactive_replay(
    effective: &EffectiveRootlessSetup,
    destination: &Path,
) -> Result<(), SetupInputError> {
    let bytes = replay_toml(effective).into_bytes();
    if let Ok(existing) = fs::symlink_metadata(destination) {
        if existing.file_type().is_symlink() || !existing.is_file() {
            return Err(SetupInputError::Plan(
                "interactive replay destination must be a regular file".into(),
            ));
        }
        return if fs::read(destination).map_err(|_| {
            SetupInputError::Plan("interactive replay destination is unreadable".into())
        })? == bytes
        {
            Ok(())
        } else {
            Err(SetupInputError::Plan(
                "interactive replay destination already exists with different content".into(),
            ))
        };
    }
    let parent = destination.parent().ok_or_else(|| {
        SetupInputError::Plan("interactive replay destination has no parent".into())
    })?;
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            SetupInputError::Plan("interactive replay destination has an unsafe name".into())
        })?;
    for sequence in 0..128_u16 {
        let temporary = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(SetupInputError::Plan(
                    "cannot create interactive replay file".into(),
                ))
            }
        };
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&temporary);
            return Err(SetupInputError::Plan(
                "cannot write interactive replay file".into(),
            ));
        }
        drop(file);
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {
                let _ = fs::remove_file(&temporary);
                let _ = File::open(parent).and_then(|directory| directory.sync_all());
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary);
                return persist_interactive_replay(effective, destination);
            }
            Err(_) => {
                let _ = fs::remove_file(&temporary);
                return Err(SetupInputError::Plan(
                    "cannot publish interactive replay file".into(),
                ));
            }
        }
    }
    Err(SetupInputError::Plan(
        "cannot create interactive replay file".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[test]
    fn setup_config_v1_merges_defaults_config_environment_and_cli_in_order() {
        let path = temp_path("merge");
        fs::write(
            &path,
            "schema_version = 1\nname = \"from-config\"\n[components]\ngit = false\nrust = true\n",
        )
        .unwrap();
        let effective = load_effective_rootless_setup(&request(&[
            "styrn",
            "setup",
            "--config",
            path.to_str().unwrap(),
            "--name",
            "from-cli",
            "--install",
            "ssh,git",
        ]))
        .unwrap();
        assert_eq!(effective.name.as_deref(), Some("from-cli"));
        assert_eq!(
            effective.component_names(),
            vec![
                "ssh-server",
                "tailscale",
                "git",
                "rust",
                "styrnd",
                "sleep-policy"
            ]
        );
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn setup_config_unknown_or_wrong_type_reports_key_and_line_without_value() {
        for input in [
            "schema_version = 1\npassword = \"do-not-show\"\n",
            "schema_version = 1\n[components]\ngit = \"do-not-show\"\n",
        ] {
            let path = temp_path("bad");
            fs::write(&path, input).unwrap();
            let error = load_effective_rootless_setup(&request(&[
                "styrn",
                "setup",
                "--config",
                path.to_str().unwrap(),
            ]))
            .unwrap_err()
            .to_string();
            assert!(error.contains("line"));
            assert!(error.contains("password") || error.contains("components.git"));
            assert!(!error.contains("do-not-show"));
            fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn setup_config_rejects_secret_shaped_or_private_key_input_without_echo() {
        for input in ["schema_version = 1\ntoken = \"not-for-output\"\n", "schema_version = 1\n[ssh]\nauthorized_keys = [\"-----BEGIN PRIVATE KEY----- never\"]\n"] {
            let path = temp_path("secret"); fs::write(&path, input).unwrap();
            let error = load_effective_rootless_setup(&request(&["styrn", "setup", "--config", path.to_str().unwrap()])).unwrap_err().to_string();
            assert!(!error.contains("not-for-output")); assert!(!error.contains("never"));
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn setup_config_rejects_invalid_enum_spelling_as_config_input() {
        let path = temp_path("enum");
        fs::write(&path, "schema_version = 1\nrole = \"not-a-role\"\n").unwrap();
        assert!(matches!(
            load_effective_rootless_setup(&request(&[
                "styrn",
                "setup",
                "--config",
                path.to_str().unwrap()
            ])),
            Err(SetupInputError::Config(_))
        ));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn rootless_setup_rejects_system_dedicated_controller_custom_root_and_mutation_flags_before_state(
    ) {
        for args in [
            &["styrn", "setup", "--scope", "system"][..],
            &["styrn", "setup", "--role", "controller"][..],
            &["styrn", "setup", "--account", "dedicated:build"][..],
            &["styrn", "setup", "--authorize-system"][..],
        ] {
            assert!(matches!(
                load_effective_rootless_setup(&request(args)),
                Err(SetupInputError::Plan(_))
            ));
        }
        let path = temp_path("root");
        fs::write(&path, "schema_version = 1\n[dirs]\nroot = \"custom\"\n").unwrap();
        assert!(matches!(
            load_effective_rootless_setup(&request(&[
                "styrn",
                "setup",
                "--config",
                path.to_str().unwrap()
            ])),
            Err(SetupInputError::Plan(_))
        ));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn setup_install_aliases_ssh_and_rejects_empty_or_unknown_components_with_valid_list() {
        assert_eq!(
            load_effective_rootless_setup(&request(&[
                "styrn",
                "setup",
                "--install",
                "ssh,ssh-server"
            ]))
            .unwrap()
            .component_names()[0],
            "ssh-server"
        );
        for value in ["ssh,,git", "unknown"] {
            let error =
                load_effective_rootless_setup(&request(&["styrn", "setup", "--install", value]))
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("valid components: ssh-server"));
        }
    }
    fn request(values: &[&str]) -> crate::cli::SetupRequest {
        crate::cli::Cli::try_parse_with_facts(
            values.iter().map(OsString::from).collect(),
            crate::cli::CliFacts::for_test(false, false, false),
        )
        .unwrap()
        .setup_request()
        .unwrap()
    }
    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "styrn-config-{label}-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
