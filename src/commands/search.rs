use crate::commands::Execute;

#[derive(clap::Parser, Debug)]
pub struct SearchCommand {
    /// The name of the article to search.
    #[clap(value_name = "FILE")]
    pub article: String,
}

// detect article language from the article words.
// If the language is not detected, it will return None.
// If the language is detected, search a valid mnemonic for the language.

// search all mnemonic words from the article by detected language.
// permutation all mnemonics by ordinal words.
// if checksum is valid, return the mnemonic.

impl Execute for SearchCommand {
    fn execute(&self) -> anyhow::Result<()> {
        todo!("Implement the search command logic")
    }
}
