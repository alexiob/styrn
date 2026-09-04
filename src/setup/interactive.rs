use std::io::{BufRead, Write};

pub(crate) fn collect_interactive_answers(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    terminal: bool,
) -> Result<super::EffectiveRootlessSetup, super::SetupInputError> {
    if !terminal {
        return Err(super::SetupInputError::Usage(
            "--interactive requires a terminal; use --config or explicit flags instead".into(),
        ));
    }
    writeln!(output, "Rootless defaults: scope=user account=current-user")
        .map_err(|_| super::SetupInputError::Plan("cannot write interactive prompt".into()))?;
    let role = prompt(input, output, "Role [worker]: ")?.unwrap_or_else(|| "worker".into());
    let components = prompt(
        input,
        output,
        "Additional components (comma-separated, blank for defaults): ",
    )?;
    let name = prompt(input, output, "Machine name (blank for native hostname): ")?;
    let effective =
        super::config::effective_from_interactive_answers(role, components.as_deref(), name)?;
    Ok(effective)
}

fn prompt(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    label: &str,
) -> Result<Option<String>, super::SetupInputError> {
    output
        .write_all(label.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| super::SetupInputError::Plan("cannot write interactive prompt".into()))?;
    let mut line = String::new();
    if input
        .read_line(&mut line)
        .map_err(|_| super::SetupInputError::Plan("cannot read interactive answer".into()))?
        == 0
    {
        return Ok(None);
    }
    let value = line.trim().to_owned();
    Ok((!value.is_empty()).then_some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn interactive_setup_requires_tty_and_collects_only_desired_state() {
        let mut output = Vec::new();
        let non_terminal = collect_interactive_answers(&mut Cursor::new(b""), &mut output, false);
        assert!(matches!(
            non_terminal,
            Err(super::super::SetupInputError::Usage(_))
        ));
        assert!(output.is_empty());

        let mut output = Vec::new();
        let effective = collect_interactive_answers(
            &mut Cursor::new(b"worker\nssh,git\nalpha\n"),
            &mut output,
            true,
        )
        .unwrap();
        assert_eq!(effective.machine_name(), Some("alpha"));
        assert!(!String::from_utf8(output).unwrap().contains("[y/N]"));
    }

    #[test]
    fn interactive_setup_effective_state_has_one_replayable_atomic_config() {
        let destination = std::env::temp_dir().join(format!(
            "styrn-interactive-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut output = Vec::new();
        let effective = collect_interactive_answers(
            &mut Cursor::new(b"worker\nssh,git\nalpha\n"),
            &mut output,
            true,
        )
        .unwrap();
        super::super::persist_interactive_replay(&effective, &destination).unwrap();
        let bytes = std::fs::read(&destination).unwrap();
        assert!(String::from_utf8(bytes.clone())
            .unwrap()
            .contains("name = \"alpha\""));
        super::super::persist_interactive_replay(&effective, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        std::fs::remove_file(destination).unwrap();
    }

    #[test]
    fn interactive_and_equivalent_flags_produce_identical_effective_state() {
        let mut output = Vec::new();
        let interactive = collect_interactive_answers(
            &mut Cursor::new(b"worker\nssh,git\nalpha\n"),
            &mut output,
            true,
        )
        .unwrap();
        let request = crate::cli::Cli::try_parse_with_facts(
            ["styrn", "setup", "--name", "alpha", "--install", "ssh,git"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect(),
            crate::cli::CliFacts::for_test(false, false, false),
        )
        .unwrap()
        .setup_request()
        .unwrap();
        assert_eq!(
            interactive,
            super::super::load_effective_rootless_setup(&request).unwrap()
        );
    }
}
