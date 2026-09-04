#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxFamily {
    Debian,
    RedHat,
    Arch,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxDistribution {
    id: String,
    id_like: Vec<String>,
    version_id: Option<String>,
    family: LinuxFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxObservationError {
    InputTooLarge,
    ContainsNul,
    InvalidUtf8,
    InvalidAssignment,
    InvalidKey,
    InvalidQuoting,
    InvalidEscape,
    DuplicateClassificationField,
    MissingId,
    ClassificationFieldTooLong,
    InvalidClassificationToken,
    ConflictingFamily,
}

fn parse_os_release(input: &[u8]) -> Result<LinuxDistribution, LinuxObservationError> {
    const MAX_INPUT_BYTES: usize = 16 * 1024;
    const MAX_CLASSIFICATION_FIELD_BYTES: usize = 255;

    if input.len() > MAX_INPUT_BYTES {
        return Err(LinuxObservationError::InputTooLarge);
    }
    if input.contains(&0) {
        return Err(LinuxObservationError::ContainsNul);
    }
    let text = std::str::from_utf8(input).map_err(|_| LinuxObservationError::InvalidUtf8)?;

    let mut id = None;
    let mut id_like = None;
    let mut version_id = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, encoded_value) = line
            .split_once('=')
            .ok_or(LinuxObservationError::InvalidAssignment)?;
        if !valid_key(key) {
            return Err(LinuxObservationError::InvalidKey);
        }
        let value = parse_value(encoded_value)?;

        let destination = match key {
            "ID" => &mut id,
            "ID_LIKE" => &mut id_like,
            "VERSION_ID" => &mut version_id,
            _ => continue,
        };
        if destination.is_some() {
            return Err(LinuxObservationError::DuplicateClassificationField);
        }
        if value.len() > MAX_CLASSIFICATION_FIELD_BYTES {
            return Err(LinuxObservationError::ClassificationFieldTooLong);
        }
        *destination = Some(value);
    }

    let id = id.ok_or(LinuxObservationError::MissingId)?;
    if !valid_classification_token(&id) {
        return Err(LinuxObservationError::InvalidClassificationToken);
    }

    let id_like = match id_like {
        Some(value) => {
            let tokens: Vec<_> = value.split_ascii_whitespace().collect();
            if tokens.is_empty() || !tokens.iter().all(|token| valid_classification_token(token)) {
                return Err(LinuxObservationError::InvalidClassificationToken);
            }
            tokens.into_iter().map(str::to_owned).collect()
        }
        None => Vec::new(),
    };

    if version_id
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err(LinuxObservationError::InvalidClassificationToken);
    }

    let family = classify_family(&id, &id_like)?;
    Ok(LinuxDistribution {
        id,
        id_like,
        version_id,
        family,
    })
}

fn valid_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn parse_value(encoded: &str) -> Result<String, LinuxObservationError> {
    let bytes = encoded.as_bytes();
    let quote = bytes
        .first()
        .copied()
        .filter(|byte| matches!(byte, b'\'' | b'"'));
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = usize::from(quote.is_some());

    while index < bytes.len() {
        let byte = bytes[index];
        if Some(byte) == quote {
            if index + 1 != bytes.len() {
                return Err(LinuxObservationError::InvalidQuoting);
            }
            return String::from_utf8(decoded).map_err(|_| LinuxObservationError::InvalidUtf8);
        }
        if quote.is_none() && matches!(byte, b'\'' | b'"') {
            return Err(LinuxObservationError::InvalidQuoting);
        }
        if quote.is_none() && byte.is_ascii_whitespace() {
            return Err(LinuxObservationError::InvalidAssignment);
        }
        if byte == b'\\' {
            index += 1;
            let escaped = bytes
                .get(index)
                .copied()
                .ok_or(LinuxObservationError::InvalidEscape)?;
            if !matches!(escaped, b'\\' | b'"' | b'\'' | b'$' | b'`') {
                return Err(LinuxObservationError::InvalidEscape);
            }
            decoded.push(escaped);
        } else {
            decoded.push(byte);
        }
        index += 1;
    }

    if quote.is_some() {
        return Err(LinuxObservationError::InvalidQuoting);
    }
    String::from_utf8(decoded).map_err(|_| LinuxObservationError::InvalidUtf8)
}

fn valid_classification_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn classify_family(id: &str, id_like: &[String]) -> Result<LinuxFamily, LinuxObservationError> {
    let exact = supported_family(id);
    let mut ancestry = None;
    for token in id_like {
        let Some(candidate) = supported_family(token) else {
            continue;
        };
        if ancestry.is_some_and(|family| family != candidate) {
            return Err(LinuxObservationError::ConflictingFamily);
        }
        ancestry = Some(candidate);
    }

    match (exact, ancestry) {
        (Some(exact), Some(ancestry)) if exact != ancestry => {
            Err(LinuxObservationError::ConflictingFamily)
        }
        (Some(exact), _) => Ok(exact),
        (None, Some(ancestry)) => Ok(ancestry),
        (None, None) => Ok(LinuxFamily::Other),
    }
}

fn supported_family(token: &str) -> Option<LinuxFamily> {
    match token {
        "debian" | "ubuntu" => Some(LinuxFamily::Debian),
        "fedora" | "rhel" | "centos" => Some(LinuxFamily::RedHat),
        "arch" | "omarchy" => Some(LinuxFamily::Arch),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/ubuntu-24.04"
    ));
    const DEBIAN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/debian-bookworm"
    ));
    const FEDORA: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/fedora"
    ));
    const RHEL: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/rhel-9"
    ));
    const ROCKY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/rocky-9"
    ));
    const ALMA: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/alma-9"
    ));
    const ORACLE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/oracle-9"
    ));
    const ARCH: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/arch"
    ));
    const OMARCHY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/omarchy"
    ));
    const OMARCHY_FUTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/omarchy-future"
    ));
    const OTHER: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/other"
    ));
    const CONFLICTING: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/conflicting"
    ));
    const DUPLICATE_ID: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/duplicate-id"
    ));
    const UNTERMINATED_QUOTE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/unterminated-quote"
    ));
    const LITERAL_SUBSTITUTION: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/linux-host/os-release/literal-substitution"
    ));

    fn distribution(
        id: &str,
        id_like: &[&str],
        version_id: Option<&str>,
        family: LinuxFamily,
    ) -> LinuxDistribution {
        LinuxDistribution {
            id: id.to_owned(),
            id_like: id_like.iter().map(|value| (*value).to_owned()).collect(),
            version_id: version_id.map(str::to_owned),
            family,
        }
    }

    #[test]
    fn removing_a_supported_exact_id_mapping_breaks_literal_distribution_fixtures() {
        let cases = [
            (
                UBUNTU,
                distribution("ubuntu", &["debian"], Some("24.04"), LinuxFamily::Debian),
            ),
            (
                DEBIAN,
                distribution("debian", &[], Some("12"), LinuxFamily::Debian),
            ),
            (
                FEDORA,
                distribution("fedora", &[], Some("42"), LinuxFamily::RedHat),
            ),
            (
                RHEL,
                distribution("rhel", &["fedora"], Some("9.6"), LinuxFamily::RedHat),
            ),
            (ARCH, distribution("arch", &[], None, LinuxFamily::Arch)),
        ];

        for (fixture, expected) in cases {
            assert_eq!(parse_os_release(fixture), Ok(expected));
        }
    }

    #[test]
    fn ignoring_single_family_id_like_breaks_derivative_distribution_fixtures() {
        let cases = [
            (
                ROCKY,
                distribution(
                    "rocky",
                    &["rhel", "centos", "fedora"],
                    Some("9.5"),
                    LinuxFamily::RedHat,
                ),
            ),
            (
                ALMA,
                distribution(
                    "almalinux",
                    &["rhel", "centos", "fedora"],
                    Some("9.5"),
                    LinuxFamily::RedHat,
                ),
            ),
            (
                ORACLE,
                distribution("ol", &["fedora"], Some("9.5"), LinuxFamily::RedHat),
            ),
            (
                OMARCHY_FUTURE,
                distribution("omarchy", &["arch"], Some("future"), LinuxFamily::Arch),
            ),
        ];

        for (fixture, expected) in cases {
            assert_eq!(parse_os_release(fixture), Ok(expected));
        }
    }

    #[test]
    fn treating_branding_as_id_breaks_current_omarchy_arch_metadata() {
        assert_eq!(
            parse_os_release(OMARCHY),
            Ok(distribution(
                "arch",
                &[],
                Some("rolling"),
                LinuxFamily::Arch,
            ))
        );
    }

    #[test]
    fn treating_every_unknown_id_as_invalid_breaks_other_distribution_support() {
        assert_eq!(
            parse_os_release(OTHER),
            Ok(distribution(
                "gentoo",
                &["linux"],
                Some("2.17"),
                LinuxFamily::Other,
            ))
        );
    }

    #[test]
    fn choosing_the_exact_family_despite_cross_family_ancestry_hides_conflicts() {
        assert_eq!(
            parse_os_release(CONFLICTING),
            Err(LinuxObservationError::ConflictingFamily)
        );
    }

    #[test]
    fn choosing_the_first_supported_ancestry_hides_unknown_id_conflicts() {
        assert_eq!(
            parse_os_release(b"ID=custom\nID_LIKE=\"linux arch debian\"\n"),
            Err(LinuxObservationError::ConflictingFamily)
        );
    }

    #[test]
    fn ignoring_same_family_ancestry_breaks_exact_id_authority() {
        assert_eq!(
            parse_os_release(b"ID=ubuntu\nID_LIKE=\"linux debian\"\n"),
            Ok(distribution(
                "ubuntu",
                &["linux", "debian"],
                None,
                LinuxFamily::Debian,
            ))
        );
    }

    #[test]
    fn executing_or_expanding_substitution_breaks_literal_value_preservation() {
        assert_eq!(
            parse_os_release(LITERAL_SUBSTITUTION),
            Ok(distribution(
                "arch",
                &[],
                Some("$(printf should-not-run)"),
                LinuxFamily::Arch,
            ))
        );
    }

    #[test]
    fn dropping_a_documented_escape_breaks_literal_escape_decoding() {
        assert_eq!(
            parse_os_release(
                br#"ID=arch
VERSION_ID="a\\b\"c\'d\$e\`f"
"#
            ),
            Ok(distribution(
                "arch",
                &[],
                Some("a\\b\"c'd$e`f"),
                LinuxFamily::Arch,
            ))
        );
    }

    #[test]
    fn rejecting_supported_line_forms_breaks_comments_quotes_and_unknown_keys() {
        assert_eq!(
            parse_os_release(
                b"  # comment\r\nNAME='Example Linux'\r\nUNKNOWN=plain-value\r\nID=arch\r\n\r\n",
            ),
            Ok(distribution("arch", &[], None, LinuxFamily::Arch))
        );
    }

    #[test]
    fn skipping_unknown_value_validation_accepts_an_unknown_escape() {
        assert_eq!(
            parse_os_release(
                br#"NAME="unsafe\q"
ID=arch
"#
            ),
            Err(LinuxObservationError::InvalidEscape)
        );
    }

    #[test]
    fn accepting_duplicate_classification_keys_makes_precedence_ambiguous() {
        for input in [
            DUPLICATE_ID,
            b"ID=arch\nID_LIKE=arch\nID_LIKE=debian\n",
            b"ID=arch\nVERSION_ID=1\nVERSION_ID=2\n",
        ] {
            assert_eq!(
                parse_os_release(input),
                Err(LinuxObservationError::DuplicateClassificationField)
            );
        }
    }

    #[test]
    fn accepting_unterminated_or_concatenated_quotes_changes_assignment_grammar() {
        assert_eq!(
            parse_os_release(UNTERMINATED_QUOTE),
            Err(LinuxObservationError::InvalidQuoting)
        );
        assert_eq!(
            parse_os_release(b"ID=\"arch\"suffix\n"),
            Err(LinuxObservationError::InvalidQuoting)
        );
    }

    #[test]
    fn accepting_missing_assignments_or_invalid_keys_weakens_line_validation() {
        assert_eq!(
            parse_os_release(b"ID=arch\nBROKEN\n"),
            Err(LinuxObservationError::InvalidAssignment)
        );
        assert_eq!(
            parse_os_release(b"ID=arch\n1NAME=value\n"),
            Err(LinuxObservationError::InvalidKey)
        );
    }

    #[test]
    fn accepting_missing_empty_or_uppercase_ids_weakens_token_validation() {
        let cases: &[&[u8]] = &[
            b"NAME=missing\n",
            b"ID=\n",
            b"ID=Ubuntu\n",
            b"ID=arch\nID_LIKE=\"\"\n",
            b"ID=custom\nID_LIKE=\"debian RHEL\"\n",
        ];
        let expected = [
            LinuxObservationError::MissingId,
            LinuxObservationError::InvalidClassificationToken,
            LinuxObservationError::InvalidClassificationToken,
            LinuxObservationError::InvalidClassificationToken,
            LinuxObservationError::InvalidClassificationToken,
        ];

        for (input, expected) in cases.iter().zip(expected) {
            assert_eq!(parse_os_release(input), Err(expected));
        }
    }

    #[test]
    fn accepting_nul_or_non_utf8_input_bypasses_text_validation() {
        assert_eq!(
            parse_os_release(b"ID=arch\nNAME=bad\0tail\n"),
            Err(LinuxObservationError::ContainsNul)
        );
        assert_eq!(
            parse_os_release(b"ID=arch\nNAME=\xff\n"),
            Err(LinuxObservationError::InvalidUtf8)
        );
    }

    #[test]
    fn moving_the_whole_input_limit_rejects_16_kib_or_accepts_its_next_byte() {
        let mut at_limit = b"ID=arch\nPADDING=".to_vec();
        at_limit.resize(16 * 1024 - 1, b'x');
        at_limit.push(b'\n');
        assert_eq!(at_limit.len(), 16 * 1024);
        assert_eq!(
            parse_os_release(&at_limit),
            Ok(distribution("arch", &[], None, LinuxFamily::Arch))
        );

        let mut over_limit = at_limit;
        over_limit.push(b'\n');
        assert_eq!(
            parse_os_release(&over_limit),
            Err(LinuxObservationError::InputTooLarge)
        );
    }

    #[test]
    fn moving_a_classification_field_limit_breaks_255_byte_boundaries() {
        let id_255 = format!("ID={}\n", "a".repeat(255));
        let id_256 = format!("ID={}\n", "a".repeat(256));
        let id_like_255 = format!("ID=custom\nID_LIKE={}\n", "a".repeat(255));
        let id_like_256 = format!("ID=custom\nID_LIKE={}\n", "a".repeat(256));
        let version_255 = format!("ID=arch\nVERSION_ID={}\n", "v".repeat(255));
        let version_256 = format!("ID=arch\nVERSION_ID={}\n", "v".repeat(256));

        assert_eq!(parse_os_release(id_255.as_bytes()).unwrap().id.len(), 255);
        assert_eq!(
            parse_os_release(id_like_255.as_bytes()).unwrap().id_like[0].len(),
            255
        );
        assert_eq!(
            parse_os_release(version_255.as_bytes())
                .unwrap()
                .version_id
                .unwrap()
                .len(),
            255
        );

        for input in [id_256, id_like_256, version_256] {
            assert_eq!(
                parse_os_release(input.as_bytes()),
                Err(LinuxObservationError::ClassificationFieldTooLong)
            );
        }
    }

    #[test]
    fn allowing_controls_in_version_id_violates_safe_text() {
        assert_eq!(
            parse_os_release(b"ID=arch\nVERSION_ID=\"one\ttwo\"\n"),
            Err(LinuxObservationError::InvalidClassificationToken)
        );
        assert_eq!(
            parse_os_release(b"ID=arch\nVERSION_ID=\x7f\n"),
            Err(LinuxObservationError::InvalidClassificationToken)
        );
    }

    #[test]
    fn carrying_raw_input_in_errors_leaks_observation_contents() {
        let marker = "fixture-secret-marker";
        let input = format!("ID=arch\nVERSION_ID=\"{marker}");
        let error = parse_os_release(input.as_bytes()).unwrap_err();

        assert_eq!(error, LinuxObservationError::InvalidQuoting);
        assert!(!format!("{error:?}").contains(marker));
    }
}
