#[derive(clap::Parser, Debug)]
pub struct SearchCommand {
    /// The name of the article to retrieve.
    #[clap(value_name = "ARTICLE")]
    pub article: String,

    /// The language of the article to retrieve.
    #[clap(hide = true, value_name = "LANGUAGE")]
    pub language: Option<String>,
}

// detect article language from the article words.
// If the language is not detected, it will return None.
// If the language is detected, search a valid mnemonic for the language.

// search all mnemonic words from the article by detected language.
// permutation all mnemonics by ordinal words.
// if checksum is valid, return the mnemonic.
