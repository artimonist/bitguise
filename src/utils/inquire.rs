pub fn inquire_password(as_salt: bool) -> anyhow::Result<String> {
    use inquire::Password;

    const INVALID_MSG: &str = "Encryption key must have at least 5 characters.";
    let validator = |v: &str| {
        if v.chars().count() < 5 {
            Ok(inquire::validator::Validation::Invalid(INVALID_MSG.into()))
        } else {
            Ok(inquire::validator::Validation::Valid)
        }
    };

    let help_msg = if as_salt {
        "Program use encryption key as salt. (Toggle display by CTRL+R)"
    } else {
        "Input encryption key. (Toggle display by CTRL+R)"
    };

    Ok(Password::new("Encryption Key: ")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_display_toggle_enabled()
        .with_custom_confirmation_message("Encryption Key (confirm):")
        .with_custom_confirmation_error_message("The keys don't match.")
        .with_validator(validator)
        .with_formatter(&|_| "Input received".into())
        .with_help_message(help_msg)
        .prompt()
        .map(|s| s.to_string())?)
}

/// Prompt user to choose a mnemonic language.
pub fn select_language(langs: &[crate::Language]) -> anyhow::Result<crate::Language> {
    use inquire::Select;

    let options = langs.iter().map(|&v| format!("{v:?}")).collect();
    let choice = Select::new("Which mnemonic language do you want?", options)
        .with_page_size(langs.len())
        .prompt()?;
    choice.parse()
}
