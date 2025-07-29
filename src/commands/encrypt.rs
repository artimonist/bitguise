use crate::utils::{inquire_password, select_language};
use crate::{commands::Execute, utils};
use disguise::{Language, Mnemonic};
use hex::ToHex;
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

impl Execute for EncryptCommand {
    fn execute(&self) -> anyhow::Result<()> {
        assert!(self.mnemonic.count() == 12, "Mnemonic must be 12 words");

        let language = match self.language {
            Some(ref lang) => lang.clone(),
            None => select_language(&Language::all())?,
        };
        let password = match self.password {
            Some(ref pass) => pass.clone(),
            None => inquire_password(false)?,
        };

        let indices = self.mnemonic.indices();
        let data: [u8; 16] = Vec::from_bits_chunk(indices.into_iter(), 11)[..16]
            .to_vec()
            .try_into()
            .unwrap();

        let mut key: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        for _ in 0..10 {
            key = Sha256::digest(key).into();

            let ciphertext = aes_ecb_encrypt(data, &key)?;
            println!("Encrypted len: {}", ciphertext.encode_hex::<String>());
            println!("Encrypted mnemonic: {}", ciphertext.len());

            let restore = aes_ecb_decrypt(ciphertext.try_into().unwrap(), &key)?;
            assert_eq!(restore, data.to_vec(), "Decryption failed");

            // generate new mnemonic from the ciphertext
            // check if new mnemonic words contains in the article
        }

        Ok(())
    }
}

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

/// Encrypts data using AES-256 in ECB mode.
fn aes_ecb_encrypt(source: [u8; 16], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let mut block = GenericArray::from(source);
    let cipher = aes::Aes256::new_from_slice(key)?;
    cipher.encrypt_block(&mut block);

    Ok(block.to_vec())
}

/// Decrypts data using AES-256 in ECB mode.
fn aes_ecb_decrypt(source: [u8; 16], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let mut block = GenericArray::from(source);
    let cipher = aes::Aes256::new_from_slice(key)?;
    cipher.decrypt_block(&mut block);

    Ok(block.to_vec())
}
