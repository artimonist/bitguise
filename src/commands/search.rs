use crate::commands::Execute;
use crate::select_language;
use disguise::Language;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

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

use Language::*;

impl Execute for SearchCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let language = select_language(&Language::all())?;

        let mut o = BufWriter::new(std::io::stdout());
        let file = File::open(&self.article)?;
        for line in BufReader::new(file).lines() {
            if matches!(language, ChineseSimplified | ChineseTraditional) {
                let mnemonics = line?
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .map(|c| {
                        language
                            .index_of(c.to_string().as_str())
                            .map_or(".".to_string(), |_| format!(" {c} "))
                    })
                    .collect::<Vec<_>>()
                    .join("");
                writeln!(o, "{mnemonics}")?;
            } else {
                let mnemonics = line?
                    .split_whitespace()
                    .map(|w| {
                        language
                            .index_of(w)
                            .map_or(".".to_string(), |_| format!(" {w} "))
                    })
                    .collect::<Vec<_>>()
                    .join("");
                writeln!(o, "{mnemonics}")?;
            }
            o.flush()?;
        }
        Ok(())
    }
}
