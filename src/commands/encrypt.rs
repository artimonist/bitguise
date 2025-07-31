use crate::utils::{inquire_password, select_language};
use disguise::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use xbits::FromBits;

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand {
    /// The mnemonic to encrypt or decrypt.
    pub mnemonic: Mnemonic,

    /// The article file name as dictionary.
    pub article: String,

    /// The target language for the mnemonic.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,

    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

impl crate::Execute for EncryptCommand {
    fn execute(&self) -> anyhow::Result<()> {
        assert!(self.mnemonic.size() == 12, "Mnemonic must be 12 words");

        let language = match self.language {
            Some(ref lang) => lang.clone(),
            None => select_language(&Language::all())?,
        };
        let password = match self.password {
            Some(ref pass) => pass.clone(),
            None => inquire_password(false)?,
        };
        let article = Article::new(&self.article, language)?;

        let start = time::Instant::now();
        for (i, mnemonic) in self
            .mnemonic
            .encrypt_times(&password, language, 2_usize.pow(32))
            .enumerate()
        {
            let count = mnemonic
                .words()
                .iter()
                .filter(|w| article.contains(w))
                .count();
            if count == mnemonic.words().len() {
                println!("");
                println!("Found valid mnemonic: {i}: {}", mnemonic);
            } else if count > 10 {
                print!("{i}: {count}, ");
            }
        }
        println!(
            "secs: {}",
            time::Instant::now().duration_since(start).as_secs() / 60
        );
        // println!("No valid mnemonic found in the article.");
        Ok(())
    }
}

use std::{collections::HashSet, time};
struct Article {
    // filename: String,
    // language: Language,
    // words: Vec<String>,
    dic: HashSet<String>,
}

impl Article {
    pub fn new(filename: &str, language: Language) -> anyhow::Result<Self> {
        use Language::*;
        let words: Vec<String> = if matches!(language, ChineseSimplified | ChineseTraditional) {
            std::fs::read_to_string(filename)?
                .chars()
                .filter_map(|c| {
                    if !c.is_whitespace()
                        && !c.is_ascii()
                        && language.index_of(&c.to_string()).is_some()
                    {
                        Some(c.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            std::fs::read_to_string(filename)?
                .split_whitespace()
                .filter_map(|w| {
                    if language.index_of(w).is_some() {
                        Some(w.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        };

        let dic = HashSet::from_iter(words.into_iter());
        Ok(Self {
            // filename: filename.to_string(),
            // language,
            // words,
            dic,
        })
    }

    pub fn contains(&self, word: &str) -> bool {
        self.dic.contains(&word.to_string())
    }
}

trait MnemonicEncryption {
    fn encrypt_times(&self, pwd: &str, lang: Language, n: usize) -> impl Iterator<Item = Mnemonic>;
}

impl MnemonicEncryption for Mnemonic {
    fn encrypt_times(&self, pwd: &str, lang: Language, n: usize) -> impl Iterator<Item = Mnemonic> {
        assert_eq!(self.size(), 12, "Mnemonic size must be 12.");

        let indices = self.indices();
        let data: [u8; 16] = Vec::from_bits_chunk(indices.into_iter(), 11)[..16]
            .to_vec()
            .try_into()
            .unwrap();

        let mut key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();
        (0..n).map(move |_| {
            key = Sha256::digest(key).into();
            let entropy = aes_ecb_encrypt(data, &key);
            Mnemonic::new(&entropy, lang).unwrap() // fixed size 16
        })
    }
}

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

/// Encrypts data using AES-256 in ECB mode.
fn aes_ecb_encrypt(source: [u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let mut block = GenericArray::from(source);

    let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 16
    cipher.encrypt_block(&mut block);

    block.into()
}

// /// Decrypts data using AES-256 in ECB mode.
// fn aes_ecb_decrypt(source: [u8; 16], key: &[u8; 32]) -> [u8; 16] {
//     let mut block = GenericArray::from(source);

//     let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 16
//     cipher.decrypt_block(&mut block);

//     block.into()
// }
