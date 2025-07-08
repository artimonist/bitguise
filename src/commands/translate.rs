use std::str::FromStr;

use anyhow::Ok;
use disguise::Language;

use super::Execute;
use crate::{Mnemonic, select_language};

#[derive(clap::Parser, Debug)]
pub struct TranslateCommand {
    /// The mnemonic to translate.
    #[clap(value_name = "MNEMONIC")]
    pub mnemonic: String,

    /// The target language for the translation.
    #[clap(hide = true, env = "ARTIMONIST_TARGET_LANGUAGE", required = false)]
    pub language: Option<Language>,
}

// create a mnemonic from words.
// get indices of the mnemonic words.
// map indices to the target language words.
// return the translated mnemonic as a string.

impl Execute for TranslateCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let mnemonic = Mnemonic::from_str(&self.mnemonic)?;
        let language = match self.language {
            Some(lang) => lang,
            None => select_language(&Language::all())?,
        };

        // translate the mnemonic to the target language
        let words = mnemonic
            .indices()
            .iter()
            .map(|&i| language.word_at(i))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        let translated = match language {
            Language::Japanese => words.join("　"),
            _ => words.join(" "),
        };

        println!("{translated}");
        Ok(())
    }
}
