use super::Language;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use xbits::{FromBits, XBits};

#[derive(Debug, Clone)]
pub struct Mnemonic {
    words: Vec<String>,
    language: Language,
}

impl Mnemonic {
    /// Create a new mnemonic from raw entropy and language.
    /// # Arguments
    /// * `entropy` - A byte slice representing the entropy.  
    ///   The entropy length must be one of: 16, 20, 24, 28, or 32 bytes.
    ///   Mnemonic lengths will be 12, 15, 18, 21, or 24 words respectively.
    /// * `language` - The language of the mnemonic.
    /// # Returns
    /// * `Ok(Mnemonic)` - If the mnemonic is successfully created.
    pub fn new(entropy: &[u8], language: Language) -> Result<Self, MnemonicError> {
        // verify length
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(MnemonicError::InvalidLength);
        }

        // calculate checksum
        let check_mask = BTreeMap::from([
            (16, 0b1111_0000),
            (20, 0b1111_1000),
            (24, 0b1111_1100),
            (28, 0b1111_1110),
            (32, 0b1111_1111),
        ])[&entropy.len()];
        let checksum = Sha256::digest(entropy)[0] & check_mask;

        // convert entropy to indices
        let indices: Vec<usize> = [entropy.to_vec(), vec![checksum]]
            .concat()
            .bits()
            .chunks(11)
            .collect();

        // convert indices to words
        let words = indices
            .iter()
            .map(|&i| language.word_at(i).unwrap_or_default().to_string())
            .collect();

        Ok(Mnemonic { words, language })
    }

    #[inline(always)]
    pub fn indices(&self) -> Vec<usize> {
        self.language.indices(self.words.iter()).unwrap()
    }

    pub fn detect_language<T>(words: impl Iterator<Item = T>) -> Vec<Language>
    where
        T: AsRef<str>,
    {
        // words common languages
        words
            .map(|w| Language::detect(w.as_ref()))
            .reduce(|mut acc, v| {
                acc.retain(|x| v.contains(x));
                acc
            })
            .unwrap_or_default()
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
        let mut languages = Mnemonic::detect_language(words.iter());

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
