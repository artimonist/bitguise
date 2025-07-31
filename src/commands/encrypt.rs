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

        for mnemonic in self.mnemonic.encrypt_times(&password, language, 100) {
            println!("{mnemonic}");
        }

        Ok(())
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

/// Decrypts data using AES-256 in ECB mode.
fn aes_ecb_decrypt(source: [u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let mut block = GenericArray::from(source);

    let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 16
    cipher.decrypt_block(&mut block);

    block.into()
}
