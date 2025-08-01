use super::aes::AesEncryption;
use crate::bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};

pub trait MnemonicEncryption {
    fn encrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic>;
    fn decrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic>;
}

impl MnemonicEncryption for Mnemonic {
    fn encrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic> {
        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();

        match self.size() {
            12 => {
                let mut entropy: [u8; 16] = self.entropy().try_into().unwrap();
                entropy.aes_ecb_encrypt(&key);
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            15 | 18 | 21 => {
                let mut entropy = self.entropy();
                {
                    let mut data: [u8; 16] = entropy[..16].try_into().unwrap();
                    data.aes_ecb_encrypt(&key);
                    entropy[..16].copy_from_slice(&data);
                }
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            24 => {
                let mut entropy: [u8; 32] = self.entropy().try_into().unwrap();
                entropy.aes_ecb_encrypt(&key);
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            _ => unreachable!(),
        }
    }

    fn decrypt(&self, pwd: &str, lang: Language) -> anyhow::Result<Mnemonic> {
        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();

        match self.size() {
            12 => {
                let mut entropy: [u8; 16] = self.entropy().try_into().unwrap();
                entropy.aes_ecb_decrypt(&key);
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            15 | 18 | 21 => {
                let mut entropy = self.entropy();
                {
                    let mut data: [u8; 16] = entropy[..16].try_into().unwrap();
                    data.aes_ecb_decrypt(&key);
                    entropy[..16].copy_from_slice(&data);
                }
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            24 => {
                let mut entropy: [u8; 32] = self.entropy().try_into().unwrap();
                entropy.aes_ecb_decrypt(&key);
                Ok(Mnemonic::new(&entropy, lang)?)
            }
            _ => unreachable!(),
        }
    }
}
