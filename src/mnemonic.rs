use crate::bip39::Mnemonic;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

trait Derivation {
    /// Derive a secret key from the passphrase and salt.
    fn derive_secret_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 64], EncError> {
        let pass: String = passphrase.nfc().collect();
        let argon_salt = {
            let scrypt_salt = ["Thanks Satoshi!".as_bytes(), salt].concat();
            let params = scrypt::Params::new(20, 8, 8, 64)?;
            let mut result = [0u8; 64];
            scrypt::scrypt(pass.as_bytes(), &scrypt_salt, &params, &mut result)?;

            let (half1, half2) = result.split_at_mut(32);
            half1[..32].xor(&half2[..32]);
            half1[..32].to_vec()
        };
        let argon = argon2::Argon2::default();
        let mut secret_key = [0u8; 64];
        argon.hash_password_into(pass.as_bytes(), &argon_salt, &mut secret_key)?;
        Ok(secret_key)
    }
}

trait Encryption: Derivation + Sized {
    /// Encrypt the mnemonic with a passphrase and salt, returning the new mnemonic and a verify word.
    /// The salt is used to extend the mnemonic length, and the verify word is used to verify the decryption.
    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<(Self, String), EncError>;

    /// Decrypt the mnemonic with a passphrase and verify word, returning the original mnemonic.
    /// If the verify word is empty, it will ignore the checksum.
    fn decrypt_extend(&self, passphrase: &str, verify: &str) -> Result<Self, EncError>;
}

impl Derivation for Mnemonic {}
impl Encryption for Mnemonic {
    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<(Self, String), EncError> {
        let result_bytes = self.word_count() / 3 * 4 + salt.len();
        debug_assert!(matches!(result_bytes, 16 | 20 | 24 | 28 | 32));

        let secret_key = Self::derive_secret_key(passphrase, salt)?;
        let (mask, aes_key) = secret_key.split_at(32);

        let entropy = &mut self.entropy();
        {
            entropy.resize(32, 0);
            entropy[..32].xor(&mask[..32]);
            let (part1, part2) = entropy.split_at_mut(16);

            let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
            cipher.encrypt_block(GenericArray::from_mut_slice(part1));
            if self.word_count() == 24 {
                cipher.encrypt_block(GenericArray::from_mut_slice(part2));
            }

            entropy.resize(self.word_count() / 3 * 4, 0);
            entropy.extend_from_slice(salt);
        }

        let new_mnemonic = Mnemonic::from_entropy(entropy, self.language())?;
        let verify_word = {
            let checksum: u16 = self.entropy().sha256_n(2)[0] as u16;
            let count_flag: u16 = 8 - self.word_count() as u16 / 3; // 4 | 3 | 2 | 1 | 0
            let verify_idx = (count_flag << 8 | checksum) as usize;
            debug_assert!(verify_idx < 2048);
            self.language().word_at(verify_idx).unwrap().to_string()
        };
        Ok((new_mnemonic, verify_word))
    }

    fn decrypt_extend(&self, passphrase: &str, verify: &str) -> Result<Self, EncError> {
        let (result_bytes, checksum) = {
            if verify.is_empty() {
                // if none verify, ignore checksum
                (self.word_count() / 3 * 4, None)
            } else if let Some(index) = self.language().index_of(verify)
                && index >> 8 < 5
            {
                // verify index contains checksum and word count flag
                ((8 - (index >> 8)) * 4, Some((index & 0xff) as u8))
            } else {
                return Err(EncError::InvalidKey);
            }
        };
        debug_assert!(matches!(result_bytes, 16 | 20 | 24 | 28 | 32));

        let entropy = &mut self.entropy();
        {
            let salt: Vec<_> = entropy.drain(result_bytes..).collect();
            let secret_key = Self::derive_secret_key(passphrase, &salt)?;
            let (mask, aes_key) = secret_key.split_at(32);

            entropy.resize(32, 0);
            let (part1, part2) = entropy.split_at_mut(16);

            let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
            cipher.decrypt_block(GenericArray::from_mut_slice(part1));
            if result_bytes == 32 {
                cipher.decrypt_block(GenericArray::from_mut_slice(part2));
            }
            entropy[..32].xor(&mask[..32]);
            entropy.resize(result_bytes, 0);
        }

        let original = Mnemonic::from_entropy(entropy, self.language())?;
        if checksum.is_some() && checksum != Some(entropy.sha256_n(2)[0]) {
            return Err(EncError::InvalidPass);
        }

        Ok(original)
    }
}

pub trait MnemonicEncryption {
    /// Encrypt the mnemonic with a passphrase and desired word count.
    /// The word count must be one of 12, 15, 18, 21, or 24.
    /// The mnemonic will be extended with random words to match the desired count.
    /// Returns the new mnemonic and a verify word for decryption.
    fn mnemonic_encrypt(&self, passphrase: &str, n: usize) -> Result<String, EncError>;

    /// Decrypt the mnemonic with a passphrase.
    /// If the mnemonic is encrypted with a verify word, it will be used to verify the decryption.
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError>;
}

impl MnemonicEncryption for str {
    fn mnemonic_encrypt(&self, passphrase: &str, n: usize) -> Result<String, EncError> {
        let original: Mnemonic = self.parse()?;
        if !matches!(n, 12 | 15 | 18 | 21 | 24) || n < original.word_count() {
            return Err(EncError::InvalidCount);
        }

        let salt = &mut vec![0u8; (n - original.word_count()) / 3 * 4];
        if !salt.is_empty() {
            rand::thread_rng().fill_bytes(salt);
        }
        let (mnemonic, verify) = original.encrypt_extend(passphrase, salt)?;
        Ok(format!("{mnemonic}; {verify}"))
    }

    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError> {
        let word_count = self.split_whitespace().count();
        if matches!(word_count, 13 | 16 | 19 | 22 | 25) {
            // Check if the mnemonic is encrypted with a verify word
            if let Some((mnemonic_str, verify)) = self.rsplit_once([' ']) {
                let mnemonic: Mnemonic = mnemonic_str.trim_end_matches(';').parse()?;
                let original = mnemonic.decrypt_extend(passphrase, verify)?;
                Ok(original.to_string())
            } else {
                Err(EncError::InvalidKey)
            }
        } else {
            let mnemonic: Mnemonic = self.parse()?;
            let original = mnemonic.decrypt_extend(passphrase, "")?;
            Ok(original.to_string())
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EncError {
    #[error("Invalid encrypted key")]
    InvalidKey,
    #[error("Invalid count")]
    InvalidCount,
    #[error("Invalid passphrase")]
    InvalidPass,
    #[error("Encrypt error: {0}")]
    EncryptError(String),
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::MnemonicError),
}

macro_rules! derive_error {
    ($e:expr, $source:ty) => {
        impl From<$source> for EncError {
            fn from(e: $source) -> Self {
                $e(e.to_string())
            }
        }
    };
}
derive_error!(EncError::EncryptError, argon2::Error);
derive_error!(EncError::EncryptError, scrypt::errors::InvalidOutputLen);
derive_error!(EncError::EncryptError, scrypt::errors::InvalidParams);

trait ByteOperation {
    fn sha256_n(&self, n: usize) -> [u8; 32];
    fn xor(&mut self, other: &Self);
}

impl ByteOperation for [u8] {
    #[inline(always)]
    fn sha256_n(&self, n: usize) -> [u8; 32] {
        use bitcoin::{hashes::Hash, hashes::sha256};
        assert!(n > 0, "Cannot hash zero times");

        let mut hash = sha256::Hash::hash(self).to_byte_array();
        for _ in 1..n {
            hash = sha256::Hash::hash(&hash).to_byte_array();
        }
        hash
    }

    #[inline(always)]
    fn xor(&mut self, other: &Self) {
        debug_assert!(self.len() == other.len());
        (0..self.len()).for_each(|i| self[i] ^= other[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_encrypt() {
        const TEST_DATA: &[&str] = &[
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音; 歌",
        ];
        for data in TEST_DATA.chunks(2) {
            assert_eq!(data[0].mnemonic_encrypt("123456", 15).unwrap(), data[1]);
            assert_eq!(data[1].mnemonic_decrypt("123456").unwrap(), data[0]);
            let mnemonic = data[1].rsplit_once(';').unwrap().0;
            assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), data[0]);
            let mnemonic = data[1].replace(';', "");
            assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), data[0]);
        }
    }
}
