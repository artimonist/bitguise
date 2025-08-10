use crate::{
    Bip38Error,
    bip39::{Language, Mnemonic},
};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use inquire::error;
use sha2::{Digest, Sha256};

trait MnemonicEnc {
    fn mnemonic_encrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic>;
    fn mnemonic_decrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic>;
}

impl MnemonicEnc for Mnemonic {
    fn mnemonic_encrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic> {
        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();

        match self.word_count() {
            12 => {
                let mut entropy: [u8; 16] = self.entropy().try_into().unwrap();
                key.aes_encrypt(&mut entropy);
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            15 | 18 | 21 => {
                let mut entropy = self.entropy();
                {
                    let mut data: [u8; 16] = entropy[..16].try_into().unwrap();
                    key.aes_encrypt(&mut data);
                    entropy[..16].copy_from_slice(&data);
                }
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            24 => {
                let mut entropy: [u8; 32] = self.entropy().try_into().unwrap();
                key.aes_encrypt(&mut entropy);
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            _ => unreachable!(),
        }
    }

    fn mnemonic_decrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic> {
        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();

        match self.word_count() {
            12 => {
                let mut entropy: [u8; 16] = self.entropy().try_into().unwrap();
                key.aes_decrypt(&mut entropy);
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            15 | 18 | 21 => {
                let mut entropy = self.entropy();
                {
                    let mut data: [u8; 16] = entropy[..16].try_into().unwrap();
                    key.aes_decrypt(&mut data);
                    entropy[..16].copy_from_slice(&data);
                }
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            24 => {
                let mut entropy: [u8; 32] = self.entropy().try_into().unwrap();
                key.aes_decrypt(&mut entropy);
                Ok(Mnemonic::from_entropy(&entropy, lang)?)
            }
            _ => unreachable!(),
        }
    }
}

/// Mnemonic encrypt strategy
pub trait Strategy {}

/// Keep mnemonic original words count
pub struct Original {}

/// Extend mnemonic words count by random salt.
/// # Example:
///   12 -> 15, 15 -> 18, 18 -> 21, 21 -> 24, 24 -> 25.
pub struct Extend {}

/// Fully mnemonic words count to 24 or 25 by random salt.
/// If words count equal to 21 or 24, this strategy is equal to `Extend`.
/// # Example:
///   12,15,18,21 -> 24, 24 -> 25.
pub struct Fully {}

impl Strategy for Original {}
impl Strategy for Extend {}
impl Strategy for Fully {}

pub trait MnemonicEncryption<T: Strategy> {
    fn mnemonic_encrypt<const N: usize>(&self, passphrase: &str) -> Result<String, EncError>;
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError>;
}

impl MnemonicEncryption<Original> for str {
    fn mnemonic_encrypt<const N: usize>(&self, passphrase: &str) -> Result<String, EncError> {
        let mnemonic: Mnemonic = self.parse()?;

        todo!("Implement mnemonic encryption logic here");
    }

    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError> {
        todo!("Implement mnemonic decryption logic here");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EncError {
    #[error("Invalid word count")]
    InvalidWordCount,
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::MnemonicError),
}

/// Trait for AES-256 encryption and decryption.
/// This trait provides methods to encrypt and decrypt data using AES-256 in ECB mode.
/// It is implemented for arrays of size 16 and 32 bytes, which are suitable for AES-256.
pub trait Aes256Encryption<const N: usize>
where
    Self: AsRef<[u8]>,
{
    /// Encrypts data using AES-256 in ECB mode.
    fn aes_encrypt(&self, data: &mut [u8; N]) {
        aes::Aes256::new(GenericArray::from_slice(self.as_ref()))
            .encrypt_block(GenericArray::from_mut_slice(data));
    }

    /// Decrypts data using AES-256 in ECB mode.
    fn aes_decrypt(&self, data: &mut [u8; N]) {
        aes::Aes256::new(GenericArray::from_slice(self.as_ref()))
            .decrypt_block(GenericArray::from_mut_slice(data));
    }
}
impl Aes256Encryption<16> for [u8; 32] {}
impl Aes256Encryption<32> for [u8; 32] {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::bip39::Language::*;

    #[test]
    fn test_mnemonic_encrypt() {
        let mnemonic = Mnemonic::from_str("派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔").unwrap();
        let password = "123456";
        let encrypted = mnemonic
            .mnemonic_encrypt(password, ChineseSimplified)
            .unwrap();
        let decrypted = encrypted
            .mnemonic_decrypt(password, ChineseSimplified)
            .unwrap();
        assert_eq!(mnemonic, decrypted);
    }
}
