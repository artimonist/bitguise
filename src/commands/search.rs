use crate::commands::Execute;
use crate::utils::select_language;
use disguise::Language;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

#[derive(clap::Parser, Debug)]
pub struct SearchCommand {
    /// The name of the article to search.
    #[clap(value_name = "FILE")]
    pub article: String,

    /// The language of the article.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,
}

// detect article language from the article words.
// If the language is not detected, it will return None.
// If the language is detected, search a valid mnemonic for the language.

// search all mnemonic words from the article by detected language.
// permutation all mnemonics by ordinal words.
// if checksum is valid, return the mnemonic.

use Language::*;

impl Execute for SearchCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let language = match self.language {
            Some(lang) => lang,
            None => select_language(&Language::all())?,
        };

        let mut o = BufWriter::new(std::io::stdout());
        let file = File::open(&self.article)?;
        for line in BufReader::new(file).lines() {
            let translate = |s: &str| {
                language
                    .index_of(s)
                    .map_or(".".to_string(), |_| format!(" {s} "))
            };

            let words = if matches!(language, ChineseSimplified | ChineseTraditional) {
                line?
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .map(|c| translate(c.to_string().as_ref()))
                    .collect::<Vec<_>>()
            } else {
                line?.split_whitespace().map(translate).collect::<Vec<_>>()
            };
            writeln!(o, "{}", words.join(""))?;
        }
        Ok(())
    }
}
