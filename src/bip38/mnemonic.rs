use super::aes::AesEncryption;
use crate::bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use xbits::FromBits;

pub trait MnemonicEncryption {
    fn encrypt(&self, pwd: &str, lang: Language) -> Mnemonic;
    fn decrypt(&self, pwd: &str, lang: Language) -> Mnemonic;
}

impl MnemonicEncryption for Mnemonic {
    fn encrypt(&self, pwd: &str, lang: Language) -> Mnemonic {
        assert_eq!(self.size(), 12);

        let indices = self.indices();
        let mut entropy: [u8; 16] = Vec::from_bits_chunk(indices.into_iter(), 11)[..16]
            .to_vec()
            .try_into()
            .unwrap();

        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();
        entropy.aes_ecb_encrypt(&key);
        Mnemonic::new(&entropy, lang).unwrap() // fixed size 16
    }

    fn decrypt(&self, pwd: &str, lang: Language) -> Mnemonic {
        assert_eq!(self.size(), 12);

        let indices = self.indices();
        let mut entropy: [u8; 16] = Vec::from_bits_chunk(indices.into_iter(), 11)[..16]
            .to_vec()
            .try_into()
            .unwrap();

        let key: [u8; 32] = Sha256::digest(pwd.as_bytes()).into();
        entropy.aes_ecb_decrypt(&key);
        Mnemonic::new(&entropy, lang).unwrap() // fixed size 16
    }
}
