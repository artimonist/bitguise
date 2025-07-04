use super::Language;

pub struct Mnemonic {
    pub words: Vec<String>,
    pub language: Language,
}

impl Mnemonic {
    pub fn new(mnemonic: &str, language: Language) -> Result<Mnemonic, MnemonicError> {
        let words: Vec<String> = mnemonic.split_whitespace().map(String::from).collect();

        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(MnemonicError::InvalidLength);
        }

        if words.iter().any(|w| language.index_of(w).is_none()) {
            return Err(MnemonicError::InvalidLanguage);
        }

        Ok(Mnemonic { words, language })
    }

    pub fn detect(mnemonic: &str) -> Result<Language, MnemonicError> {
        // verify length
        let words: Vec<_> = mnemonic.split_whitespace().collect();
        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(MnemonicError::InvalidLength);
        }

        // detect languages
        let languages = words
            .into_iter()
            .map(|w| Language::detect(w))
            .reduce(|mut acc, v| {
                acc.retain(|x| v.contains(x));
                acc
            })
            .unwrap_or_default();
        match languages.len() {
            0 => return Err(MnemonicError::InvalidLanguage),
            1 => return Ok(*languages.first().unwrap()),
            2.. => return Err(MnemonicError::InconclusiveLanguage(languages)),
        }
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let language = Mnemonic::detect(s)?;
        Mnemonic::new(s, language)
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error("invalid mnemonic length")]
    InvalidLength,

    #[error("invalid mnemonic language")]
    InvalidLanguage,

    #[error("inconclusive mnemonic language")]
    InconclusiveLanguage(Vec<Language>),

    #[error("invalid checksum")]
    InvalidChecksum,
}
