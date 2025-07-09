use crate::{commands::Execute, select_language};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use disguise::{Language, Mnemonic};
use std::str::FromStr;
use xbits::FromBits; // Or Aes128Gcm

#[derive(clap::Parser, Debug)]
pub struct TransformCommand {
    /// The mnemonic to transform.
    #[clap(value_name = "MNEMONIC")]
    pub mnemonic: String,

    /// The target language for the mnemonic.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,

    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

// encrypt mnemonic entropy.
// generate a mnemonic from new entropy.

impl Execute for TransformCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let mnemonic = Mnemonic::from_str(&self.mnemonic)?;
        let language = match self.language {
            Some(lang) => lang,
            None => select_language(&Language::all())?,
        };
        let mnemonic_transformed = encrypt_mnemonic(&mnemonic, language)?;
        println!("Transformed mnemonic: {}", mnemonic_transformed.to_string());
        Ok(())
    }
}

fn encrypt_mnemonic(mnemonic: &Mnemonic, language: Language) -> anyhow::Result<Mnemonic> {
    let indices = mnemonic.indices();
    let mut entropy = Vec::from_bits_chunk(indices.into_iter(), 11);
    entropy.pop();

    // For demonstration, use a fixed key and nonce. In production, use securely generated values.
    let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(nonce, entropy.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    // Optionally, you may want to store nonce/ciphertext together or handle them differently.
    // For now, just use the ciphertext as the new entropy.
    let mnemonic_transformed = Mnemonic::new(&ciphertext, language)?;
    Ok(mnemonic_transformed)
    // let mnemonic_transformed = Mnemonic::new(&mnemonic.entropy(), language)?;
    // // if mnemonic_transformed.indices() != indices {
    // //     return Err(anyhow::anyhow!("Mnemonic transformation failed"));
    // // }
    // Ok(mnemonic_transformed)
}
