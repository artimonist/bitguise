use crate::commands::Execute;
use crate::utils::inquire_password;
use disguise::{Language, Mnemonic};
use hex::ToHex;
use sha2::{Digest, Sha256};
use xbits::FromBits;

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand {
    /// The mnemonic to encrypt or decrypt.
    pub mnemonic: Mnemonic,

    /// The target language for the mnemonic.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,

    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

impl Execute for EncryptCommand {
    fn execute(&self) -> anyhow::Result<()> {
        assert!(
            self.mnemonic.count() == 12,
            "Mnemonic must be 12 words long"
        );

        let password = match self.password {
            Some(ref pass) => pass.clone(),
            None => inquire_password(false)?,
        };

        let indices = self.mnemonic.indices();
        let buf = Vec::from_bits_chunk(indices.into_iter(), 11)[..16].to_vec();
        assert_eq!(buf.len(), 16, "Buffer must be 16 bytes long");
        let source: [u8; 16] = buf[..16]
            .to_vec()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid buffer length"))?;

        let mut key = Sha256::digest(password.as_bytes());
        for _ in 0..10 {
            key = Sha256::digest(key);

            let ciphertext = aes_ecb_encrypt(source, key.as_slice())?;
            println!("Encrypted len: {}", ciphertext.encode_hex::<String>());
            println!("Encrypted mnemonic: {}", ciphertext.len());

            let restore = aes_ecb_decrypt(ciphertext.try_into().unwrap(), key.as_slice())?;
            assert_eq!(restore, source.to_vec(), "Decryption failed");
        }

        Ok(())
    }
}

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

/// Encrypts data using AES-256 in ECB mode.
fn aes_ecb_encrypt(source: [u8; 16], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut block = GenericArray::from(source);
    let cipher = aes::Aes256::new_from_slice(key)?;
    cipher.encrypt_block(&mut block);

    Ok(block.to_vec())
}

/// Decrypts data using AES-256 in ECB mode.
fn aes_ecb_decrypt(source: [u8; 16], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut block = GenericArray::from(source);
    let cipher = aes::Aes256::new_from_slice(key)?;
    cipher.decrypt_block(&mut block);

    Ok(block.to_vec())
}
