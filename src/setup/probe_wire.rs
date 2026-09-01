use super::probe::ProbeId;
use super::probe::{
    FindingSeverity, ProbeDescriptorSpec, ProbeStatus, RemediationSpec, StyrnCommand, WorkerProbe,
};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Remediation {
    summary: String,
    command: Option<StyrnCommand>,
}

impl Remediation {
    fn from_spec(spec: &RemediationSpec) -> Self {
        Self {
            summary: safe_static_text(spec.summary(), "remediation unavailable"),
            command: spec.command(),
        }
    }
}

impl Serialize for Remediation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output =
            serializer.serialize_struct("Remediation", usize::from(self.command.is_some()) + 1)?;
        output.serialize_field(
            "summary",
            &safe_static_text(&self.summary, "remediation unavailable"),
        )?;
        if let Some(command) = self.command {
            output.serialize_field("styrn_args", command.args())?;
        }
        output.end()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeDescriptor {
    id: ProbeId,
    label: String,
    failure_severity: FindingSeverity,
    remediation: Option<Remediation>,
}

impl ProbeDescriptor {
    fn from_spec(spec: &ProbeDescriptorSpec) -> Self {
        Self {
            id: spec.id().clone(),
            label: safe_static_text(spec.label(), "worker probe"),
            failure_severity: spec.failure_severity(),
            remediation: spec.remediation().map(Remediation::from_spec),
        }
    }

    pub(crate) fn id(&self) -> &ProbeId {
        &self.id
    }
}

impl Serialize for ProbeDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct(
            "ProbeDescriptor",
            usize::from(self.remediation.is_some()) + 3,
        )?;
        output.serialize_field("id", &self.id)?;
        output.serialize_field("label", &safe_static_text(&self.label, "worker probe"))?;
        output.serialize_field("failure_severity", &self.failure_severity)?;
        if let Some(remediation) = &self.remediation {
            output.serialize_field("remediation", remediation)?;
        }
        output.end()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeObservation {
    descriptor: ProbeDescriptor,
    status: ProbeStatus,
}

impl ProbeObservation {
    fn new(descriptor: ProbeDescriptor, status: ProbeStatus) -> Self {
        Self {
            descriptor,
            status: sanitize_status(status),
        }
    }

    pub(crate) fn descriptor(&self) -> &ProbeDescriptor {
        &self.descriptor
    }

    pub(crate) fn status(&self) -> &ProbeStatus {
        &self.status
    }
}

impl Serialize for ProbeObservation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let status = sanitize_status(self.status.clone());
        let mut output = serializer.serialize_struct("ProbeObservation", 2)?;
        output.serialize_field("descriptor", &self.descriptor)?;
        output.serialize_field("status", &SerializedProbeStatus::from(&status))?;
        output.end()
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SerializedProbeStatus<'a> {
    Absent,
    Present {
        version: Option<&'a str>,
        healthy: bool,
    },
    Broken {
        reason: &'a str,
    },
    Unknowable {
        reason: &'a str,
    },
}

impl<'a> From<&'a ProbeStatus> for SerializedProbeStatus<'a> {
    fn from(status: &'a ProbeStatus) -> Self {
        match status {
            ProbeStatus::Absent => Self::Absent,
            ProbeStatus::Present { version, healthy } => Self::Present {
                version: version.as_deref(),
                healthy: *healthy,
            },
            ProbeStatus::Broken { reason } => Self::Broken { reason },
            ProbeStatus::Unknowable { reason } => Self::Unknowable { reason },
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ObservedState {
    observations: Vec<ProbeObservation>,
}

impl ObservedState {
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &ProbeObservation> {
        self.observations.iter()
    }

    pub(crate) fn get(&self, id: &ProbeId) -> Option<&ProbeObservation> {
        self.observations
            .iter()
            .find(|observation| observation.descriptor.id == *id)
    }

    pub(crate) fn setup_observations(&self) -> impl ExactSizeIterator<Item = &ProbeObservation> {
        self.iter()
    }

    pub(crate) fn doctor_findings(&self) -> Vec<DoctorFinding> {
        self.iter().map(DoctorFinding::from_observation).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorFindingState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DoctorFinding {
    id: ProbeId,
    state: DoctorFindingState,
    severity: FindingSeverity,
    message: String,
    remediation: Option<Remediation>,
}

impl DoctorFinding {
    fn from_observation(observation: &ProbeObservation) -> Self {
        let (state, detail) = match observation.status() {
            ProbeStatus::Absent => (DoctorFindingState::Fail, "subject is absent"),
            ProbeStatus::Present { healthy: true, .. } => (DoctorFindingState::Pass, "healthy"),
            ProbeStatus::Present { healthy: false, .. } => {
                (DoctorFindingState::Fail, "present but unhealthy")
            }
            ProbeStatus::Broken { reason } => (DoctorFindingState::Fail, reason.as_str()),
            ProbeStatus::Unknowable { reason } => (DoctorFindingState::Unknown, reason.as_str()),
        };
        let descriptor = observation.descriptor();
        Self {
            id: descriptor.id.clone(),
            state,
            severity: descriptor.failure_severity,
            message: format!(
                "{}: {detail}",
                safe_static_text(&descriptor.label, "worker probe")
            ),
            remediation: descriptor.remediation.clone(),
        }
    }

    pub(crate) fn id(&self) -> &ProbeId {
        &self.id
    }

    pub(crate) fn state(&self) -> DoctorFindingState {
        self.state
    }
}

impl Serialize for DoctorFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer
            .serialize_struct("DoctorFinding", usize::from(self.remediation.is_some()) + 4)?;
        output.serialize_field("id", &self.id)?;
        output.serialize_field("state", &self.state)?;
        output.serialize_field("severity", &self.severity)?;
        output.serialize_field(
            "message",
            &safe_runtime_text(&self.message, "worker probe finding"),
        )?;
        if let Some(remediation) = &self.remediation {
            output.serialize_field("remediation", remediation)?;
        }
        output.end()
    }
}

pub(super) fn validate_static_text(value: &str) -> bool {
    is_safe_text(value)
}

pub(super) fn observe(probes: &[Box<dyn WorkerProbe>]) -> ObservedState {
    ObservedState {
        observations: probes
            .iter()
            .map(|probe| {
                let status = match probe.observe() {
                    Ok(status) => status,
                    Err(failure) => ProbeStatus::Unknowable {
                        reason: failure.canonical_reason().to_owned(),
                    },
                };
                ProbeObservation::new(ProbeDescriptor::from_spec(probe.descriptor()), status)
            })
            .collect(),
    }
}

fn sanitize_status(status: ProbeStatus) -> ProbeStatus {
    match status {
        ProbeStatus::Absent => ProbeStatus::Absent,
        ProbeStatus::Present { version, healthy } => ProbeStatus::Present {
            version: version.filter(|version| is_safe_version(version)),
            healthy,
        },
        ProbeStatus::Broken { reason } => ProbeStatus::Broken {
            reason: canonical_reason(&reason),
        },
        ProbeStatus::Unknowable { reason } => ProbeStatus::Unknowable {
            reason: canonical_reason(&reason),
        },
    }
}

fn is_safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && is_safe_text(value)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'+'))
}

fn canonical_reason(reason: &str) -> String {
    let normalized = reason.to_ascii_lowercase();
    if normalized.contains("permission") || normalized.contains("eacces") {
        "permission denied".to_owned()
    } else if normalized.contains("unreadable") {
        "state unreadable".to_owned()
    } else if normalized.contains("malformed") || normalized.contains("unsupported") {
        "output was malformed or unsupported".to_owned()
    } else if normalized.contains("prerequisite") {
        "required prerequisite was unavailable".to_owned()
    } else if normalized.contains("inconsistent") || normalized.contains("corrupt") {
        "internally inconsistent state".to_owned()
    } else {
        "probe observation failed".to_owned()
    }
}

fn safe_static_text(value: &str, fallback: &'static str) -> String {
    if is_safe_text(value) {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn safe_runtime_text(value: &str, fallback: &'static str) -> String {
    safe_static_text(value, fallback)
}

fn is_safe_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control) && !looks_secret_shaped(value)
}

fn looks_secret_shaped(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    value.chars().any(char::is_control)
        || normalized.contains("-----begin")
        || contains_sensitive_marker_value(value)
        || contains_embedded_compact_jwt(value)
        || contains_credential_prefix(value)
}

fn contains_embedded_compact_jwt(value: &str) -> bool {
    let mut search_start = 0;
    while let Some(relative_start) = value[search_start..].find("eyJ") {
        let start = search_start + relative_start;
        let end = value[start..]
            .char_indices()
            .find(|(_, character)| {
                !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.')
            })
            .map_or(value.len(), |(offset, _)| start + offset);
        if is_compact_jwt(&value[start..end]) {
            return true;
        }
        search_start = start + "eyJ".len();
    }
    false
}

fn contains_sensitive_marker_value(value: &str) -> bool {
    let tokens = lexical_tokens(value);
    tokens.iter().enumerate().any(|(index, token)| {
        matches!(token, LexToken::Word(_))
            && credential_marker_end(&tokens, index)
                .and_then(|marker_end| marker_value_after(&tokens, marker_end))
                .is_some_and(|value| !is_safe_marker_prose(&tokens, value))
    })
}

const CREDENTIAL_MARKER_FAMILIES: &[&[&str]] = &[
    &["authorization", "bearer", "token"],
    &["authorization", "token"],
    &["bearer", "token"],
    &["access", "token"],
    &["refresh", "token"],
    &["session", "token"],
    &["access", "key"],
    &["private", "key"],
    &["secret", "key"],
    &["client", "secret"],
    &["api", "key"],
    &["auth", "token"],
    &["id", "token"],
];

const SINGLE_CREDENTIAL_MARKERS: &[&str] = &[
    "apikey",
    "auth",
    "authorization",
    "password",
    "privatekey",
    "secret",
    "accesskey",
    "credential",
    "credentials",
    "token",
    "bearer",
];

fn credential_marker_end(tokens: &[LexToken<'_>], index: usize) -> Option<usize> {
    let LexToken::Word(word) = tokens[index] else {
        return None;
    };
    let word = normalized_word(word);
    let mut longest = SINGLE_CREDENTIAL_MARKERS
        .iter()
        .any(|marker| *marker == word)
        .then_some(index);

    for family in CREDENTIAL_MARKER_FAMILIES {
        if let Some(end) = marker_family_end(tokens, index, family) {
            longest = Some(longest.map_or(end, |previous| previous.max(end)));
        }
    }
    longest
}

fn marker_family_end(tokens: &[LexToken<'_>], start: usize, family: &[&str]) -> Option<usize> {
    let mut index = start;
    for (position, expected) in family.iter().enumerate() {
        let LexToken::Word(word) = tokens[index] else {
            return None;
        };
        if normalized_word(word) != *expected {
            return None;
        }
        if position + 1 == family.len() {
            return Some(index);
        }
        index = next_marker_word(tokens, index + 1)?;
    }
    None
}

fn next_marker_word(tokens: &[LexToken<'_>], start: usize) -> Option<usize> {
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            LexToken::Gap | LexToken::Wrapper | LexToken::Joiner | LexToken::FamilyJoiner => {
                continue
            }
            LexToken::Word(_) => return Some(index),
            LexToken::Separator | LexToken::Boundary => return None,
        }
    }
    None
}

fn marker_value_after(tokens: &[LexToken<'_>], start: usize) -> Option<usize> {
    for (index, token) in tokens.iter().enumerate().skip(start + 1) {
        match token {
            LexToken::Gap
            | LexToken::Wrapper
            | LexToken::Joiner
            | LexToken::FamilyJoiner
            | LexToken::Separator => continue,
            LexToken::Word(_) => return Some(index),
            LexToken::Boundary => return None,
        }
    }
    None
}

const SAFE_MARKER_NOUNS: &[&str] = &[
    "cache",
    "service",
    "process",
    "support",
    "state",
    "status",
    "authentication",
    "capability",
    "scheme",
    "header",
    "reset",
    "refresh",
    "rotation",
    "permissions",
    "file",
    "policy",
];

const COPULAS: &[&str] = &["is", "are", "was", "were", "be", "been", "being"];
const STATUS_PREDICATES: &[&str] = &[
    "enabled",
    "healthy",
    "disabled",
    "unhealthy",
    "absent",
    "available",
    "unavailable",
];

fn is_safe_marker_prose(tokens: &[LexToken<'_>], value_index: usize) -> bool {
    let LexToken::Word(first) = tokens[value_index] else {
        return false;
    };
    let first = normalized_word(first);
    if COPULAS.contains(&first.as_str()) {
        return next_context_word(tokens, value_index + 1).is_some_and(|predicate| {
            matches!(tokens[predicate], LexToken::Word(word) if STATUS_PREDICATES.contains(&normalized_word(word).as_str()))
                && clause_ends_after(tokens, predicate + 1)
        });
    }

    let mut current = value_index;
    loop {
        let LexToken::Word(noun) = tokens[current] else {
            return false;
        };
        if !SAFE_MARKER_NOUNS.contains(&normalized_word(noun).as_str()) {
            return false;
        }
        let Some(next) = next_context_word(tokens, current + 1) else {
            return separator_status_clause(tokens, current + 1)
                .unwrap_or_else(|| clause_ends_after(tokens, current + 1));
        };
        let LexToken::Word(next_word) = tokens[next] else {
            return false;
        };
        if COPULAS.contains(&normalized_word(next_word).as_str()) {
            return next_context_word(tokens, next + 1).is_some_and(|predicate| {
                matches!(tokens[predicate], LexToken::Word(word) if STATUS_PREDICATES.contains(&normalized_word(word).as_str()))
                    && clause_ends_after(tokens, predicate + 1)
            });
        }
        current = next;
    }
}

fn next_context_word(tokens: &[LexToken<'_>], start: usize) -> Option<usize> {
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            LexToken::Gap | LexToken::Wrapper | LexToken::Joiner => continue,
            LexToken::Word(_) => return Some(index),
            LexToken::Separator | LexToken::Boundary | LexToken::FamilyJoiner => return None,
        }
    }
    None
}

fn clause_ends_after(tokens: &[LexToken<'_>], start: usize) -> bool {
    let mut index = start;
    while let Some(token) = tokens.get(index) {
        match token {
            LexToken::Gap | LexToken::Boundary | LexToken::FamilyJoiner | LexToken::Joiner => {
                index += 1;
            }
            LexToken::Wrapper => {
                index += 1;
                let mut has_qualifier = false;
                while let Some(qualifier) = tokens.get(index) {
                    match qualifier {
                        LexToken::Gap => index += 1,
                        LexToken::Word(word)
                            if matches!(
                                normalized_word(word).as_str(),
                                "managed"
                                    | "system"
                                    | "default"
                                    | "local"
                                    | "remote"
                                    | "configured"
                                    | "required"
                                    | "optional"
                            ) =>
                        {
                            has_qualifier = true;
                            index += 1;
                        }
                        LexToken::Wrapper if has_qualifier => {
                            index += 1;
                            break;
                        }
                        _ => return false,
                    }
                }
                if !has_qualifier {
                    return false;
                }
            }
            LexToken::Separator | LexToken::Word(_) => return false,
        }
    }
    true
}

fn separator_status_clause(tokens: &[LexToken<'_>], start: usize) -> Option<bool> {
    let mut index = start;
    while matches!(tokens.get(index), Some(LexToken::Gap)) {
        index += 1;
    }
    if !matches!(tokens.get(index), Some(LexToken::Separator)) {
        return None;
    }
    index += 1;
    while matches!(tokens.get(index), Some(LexToken::Gap)) {
        index += 1;
    }
    let LexToken::Word(predicate) = tokens.get(index)? else {
        return Some(false);
    };
    Some(
        STATUS_PREDICATES.contains(&normalized_word(predicate).as_str())
            && clause_ends_after(tokens, index + 1),
    )
}

fn contains_credential_prefix(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    [
        "sk-",
        "sk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "tskey-",
        "tskey_",
    ]
    .iter()
    .any(|prefix| {
        lowercase.match_indices(prefix).any(|(start, _)| {
            let left_boundary = lowercase[..start]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric());
            left_boundary
                && lowercase[start + prefix.len()..]
                    .chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                    })
                    .take(4)
                    .count()
                    == 4
        })
    })
}

#[derive(Clone, Copy)]
enum LexToken<'a> {
    Word(&'a str),
    Separator,
    Boundary,
    Gap,
    Wrapper,
    Joiner,
    FamilyJoiner,
}

fn lexical_tokens(value: &str) -> Vec<LexToken<'_>> {
    let mut tokens = Vec::new();
    let mut word_start = None;
    for (index, character) in value.char_indices() {
        let is_word = character.is_ascii_alphanumeric();
        let is_separator = matches!(character, ':' | '=');
        let is_gap = character.is_whitespace();
        let is_wrapper = matches!(character, '(' | ')' | '[' | ']' | '{' | '}');
        let is_family_joiner = matches!(character, '.' | '?');
        let is_boundary = matches!(character, ',' | ';' | '&') || !character.is_ascii();
        let is_joiner = !is_word && !is_separator && !is_gap && !is_wrapper && !is_boundary;
        if is_word {
            word_start.get_or_insert(index);
            continue;
        }
        if let Some(start) = word_start.take() {
            tokens.push(LexToken::Word(&value[start..index]));
        }
        tokens.push(if is_separator {
            LexToken::Separator
        } else if is_gap {
            LexToken::Gap
        } else if is_wrapper {
            LexToken::Wrapper
        } else if is_family_joiner {
            LexToken::FamilyJoiner
        } else if is_joiner {
            LexToken::Joiner
        } else {
            LexToken::Boundary
        });
    }
    if let Some(start) = word_start {
        tokens.push(LexToken::Word(&value[start..]));
    }
    tokens
}

fn normalized_word(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn is_compact_jwt(value: &str) -> bool {
    is_compact_jwt_segments(value.trim_matches('.'))
}

fn is_compact_jwt_segments(candidate: &str) -> bool {
    let segments: Vec<_> = candidate.split('.').collect();
    if !matches!(segments.len(), 3 | 5)
        || segments.iter().any(|segment| segment.is_empty())
        || segments.iter().any(|segment| {
            !segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        })
    {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(segments[0])
        .or_else(|_| URL_SAFE.decode(segments[0]))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|header| header.as_object().cloned())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        contains_credential_prefix, contains_embedded_compact_jwt, contains_sensitive_marker_value,
        credential_marker_end, lexical_tokens, marker_value_after, LexToken,
    };

    #[test]
    fn tokenizer_preserves_joiners_wrappers_and_clause_boundaries() {
        assert!(matches!(
            lexical_tokens("private [key]=abc123").as_slice(),
            [
                LexToken::Word("private"),
                LexToken::Gap,
                LexToken::Wrapper,
                LexToken::Word("key"),
                LexToken::Wrapper,
                LexToken::Separator,
                LexToken::Word("abc123"),
            ]
        ));
        assert!(matches!(
            lexical_tokens("token:, cache").as_slice(),
            [
                LexToken::Word("token"),
                LexToken::Separator,
                LexToken::Boundary,
                LexToken::Gap,
                LexToken::Word("cache"),
            ]
        ));
        assert!(matches!(
            lexical_tokens("token!abc123").as_slice(),
            [
                LexToken::Word("token"),
                LexToken::Joiner,
                LexToken::Word("abc123"),
            ]
        ));
    }

    #[test]
    fn marker_matcher_prefers_the_longest_compound_family() {
        let tokens = lexical_tokens("authorization_bearer_token abc123");
        let marker_end = credential_marker_end(&tokens, 0);
        assert_eq!(marker_end, Some(4));
        assert_eq!(marker_value_after(&tokens, marker_end.unwrap()), Some(6));
    }

    #[test]
    fn marker_grammar_detects_unassigned_joined_and_wrapped_values() {
        for value in [
            "password hunter2",
            "api key abc123",
            "API_KEY abc123",
            "auth_token abc123",
            "bearer-token abc123",
            "authorization_bearer_token abc123",
            "private [key]=abc123",
            "https://host/path?token=abc123",
            "token-abc123",
            "private_key_abc123",
            "token.value",
            "password.hunter2",
            "api.key.abc123",
            "private.key.hunter2",
        ] {
            assert!(contains_sensitive_marker_value(value), "{value:?}");
        }
    }

    #[test]
    fn status_prose_must_consume_its_entire_clause() {
        for value in [
            "token is absent hunter2",
            "password is unavailable hunter2",
            "api key support is enabled abc123",
            "bearer token cache is healthy abc123",
            "token cache is healthy: abc123",
        ] {
            assert!(contains_sensitive_marker_value(value), "{value:?}");
        }
        for value in [
            "Password reset service is enabled.",
            "Token refresh service is healthy.",
            "API key rotation is enabled.",
            "Private key permissions status is healthy.",
            "Token status: absent.",
            "Private key file is absent.",
            "Password policy is enabled.",
            "Token status is absent!",
            "Token status is absent (managed).",
        ] {
            assert!(!contains_sensitive_marker_value(value), "{value:?}");
        }
    }

    #[test]
    fn marker_matcher_connects_dot_and_query_key_forms() {
        for value in [
            "api.key=abc123",
            "private.key=abc123",
            "access.key=abc123",
            "secret.key=abc123",
            "api?key=abc123",
        ] {
            assert!(contains_sensitive_marker_value(value), "{value:?}");
        }
    }

    #[test]
    fn credential_prefix_scanner_finds_embedded_prefixes() {
        for value in [
            "prefix/sk_live_do-not-leak",
            "https://host/sk_live_do-not-leak",
            "diagnostic-sk_live_do-not-leak",
            "foo?ghp_do-not-leak",
            "prefix/ghp_do-not-leak",
        ] {
            assert!(contains_credential_prefix(value), "{value:?}");
        }
        for value in [
            "task_worker",
            "task_status",
            "flask_service",
            "mask_enabled",
        ] {
            assert!(!contains_credential_prefix(value), "{value:?}");
        }
    }

    #[test]
    fn jwt_scanner_detects_three_and_five_segment_json_object_headers() {
        for value in [
            "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.signature",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d",
            "prefix/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "diagnostic-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "diagnostic_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "diagnosticeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        ] {
            assert!(contains_embedded_compact_jwt(value), "{value:?}");
        }
    }
}
