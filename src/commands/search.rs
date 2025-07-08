use crate::commands::Execute;
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

impl Execute for SearchCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let mut languages = detect_language(&self.article)?;
        if languages.is_empty() {
            return Err(anyhow::anyhow!("No valid language detected."));
        }
        debug_assert!(languages.len() == 1 || languages.len() == 2);

        let mut o = BufWriter::new(std::io::stdout());
        // let mut words: Vec<String> = Vec::new();
        let file = File::open(&self.article)?;
        for line in BufReader::new(file).lines() {
            // println!("Processing line: {:?}", line);
            for word in line?.split_whitespace() {
                let langs: Vec<_> = languages
                    .iter()
                    .filter(|v| v.index_of(word).is_some())
                    .collect();
                match langs.len() {
                    0 => {
                        write!(o, "x")?;
                        continue;
                    }
                    _ => {
                        write!(o, " {word} ")?;
                        if langs.len() < languages.len() {
                            languages = langs.into_iter().cloned().collect();
                        }
                    }
                }
                // write!(o, " ")?;
            }
            writeln!(o)?;
            o.flush()?;
        }
        Ok(())
    }
}

fn detect_language(file: &str) -> anyhow::Result<Vec<Language>> {
    let reader = BufReader::new(File::open(file)?);
    for line in reader.lines() {
        for word in line?.split_whitespace() {
            match Language::detect(word) {
                languages if languages.len() > 0 => return Ok(languages),
                _ => continue,
            }
        }
    }
    Ok(vec![])
}

// fn split_words<'a>(
//     line: &'a str,
//     languages: &[Language],
// ) -> Box<dyn Iterator<Item = &'a str> + 'a> {
//     if languages.contains(&Language::ChineseSimplified)
//         || languages.contains(&Language::ChineseTraditional)
//     {
//         Box::new(
//             (0..line.len())
//                 .filter(|&i| line.is_char_boundary(i))
//                 .map(|i| &line[i..]),
//         )
//     } else {
//         Box::new(line.split_whitespace())
//     }
// }
