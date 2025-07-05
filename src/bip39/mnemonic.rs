use super::Language;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use xbits::FromBits;

#[derive(Debug, Clone)]
pub struct Mnemonic {
    words: Vec<String>,
    language: Language,
}

impl Mnemonic {
    pub fn detect_language<T>(words: impl Iterator<Item = T>) -> Result<Language, MnemonicError>
    where
        T: AsRef<str>,
    {
        // words common languages
        let mut languages = words
            .map(|w| Language::detect(w.as_ref()))
            .reduce(|mut acc, v| {
                acc.retain(|x| v.contains(x));
                acc
            })
            .unwrap_or_default();

        // return language
        match languages.len() {
            0 => Err(MnemonicError::InvalidLanguage),
            1 => Ok(languages.pop().unwrap()),
            2.. => Err(MnemonicError::InconclusiveLanguage(languages)),
        }
    }

    pub fn verify_checksum(indices: &[usize]) -> Result<(), MnemonicError> {
        const CHECK_MASK_ALL: [(usize, u8); 5] = [
            (12, 0b1111_0000),
            (15, 0b1111_1000),
            (18, 0b1111_1100),
            (21, 0b1111_1110),
            (24, 0b1111_1111),
        ];

        let check_mask = *BTreeMap::from(CHECK_MASK_ALL)
            .get(&indices.len())
            .ok_or(MnemonicError::InvalidLength)?;

        let mut entropy = Vec::from_bits_chunk(indices.iter().copied(), 11);
        let tail = entropy.pop().unwrap();
        let checksum = Sha256::digest(&entropy)[0];

        if checksum & check_mask != tail {
            return Err(MnemonicError::InvalidChecksum);
        }
        Ok(())
    }

    #[inline(always)]
    pub fn indices(&self) -> Vec<usize> {
        self.language.indices(self.words.iter()).unwrap()
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // verify length
        let words: Vec<&str> = s.split_whitespace().collect();
        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(MnemonicError::InvalidLength);
        }

        // detect languages
        let mut languages = match Mnemonic::detect_language(words.iter()) {
            Ok(v) => Ok(vec![v]),
            Err(MnemonicError::InconclusiveLanguage(vs)) => Ok(vs),
            Err(e) => Err(e),
        }?;

        // verify checksum
        languages.retain(|&language| {
            if let Ok(indices) = language.indices(words.iter()) {
                Mnemonic::verify_checksum(&indices).is_ok()
            } else {
                false
            }
        });

        // return mnemonic
        match languages.len() {
            0 => Err(MnemonicError::InvalidChecksum),
            1 => Ok(Mnemonic {
                words: words.into_iter().map(String::from).collect(),
                language: languages.pop().unwrap(),
            }),
            2.. => Err(MnemonicError::InconclusiveLanguage(languages)),
        }
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}: \"{}\"", self.language, self.words.join(" "))
    }
}

trait Indices {
    fn indices<T>(&self, words: impl Iterator<Item = T>) -> Result<Vec<usize>, MnemonicError>
    where
        T: AsRef<str>;
}
impl Indices for Language {
    fn indices<T>(&self, words: impl Iterator<Item = T>) -> Result<Vec<usize>, MnemonicError>
    where
        T: AsRef<str>,
    {
        words
            .map(|w| self.index_of(w.as_ref()))
            .collect::<Option<Vec<_>>>()
            .ok_or(MnemonicError::InvalidLanguage)
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

    #[error("invalid mnemonic checksum")]
    InvalidChecksum,
}
