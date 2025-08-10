use crate::bip39::Mnemonic;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use unicode_normalization::UnicodeNormalization;

trait Derivation {
    /// Generate salt from passphrase
    fn passphrase_to_salt(passphrase: &str) -> Result<[u8; 32], EncError> {
        let pass: String = passphrase.nfc().collect();
        let salt = "Thanks Satoshi!";
        let params = scrypt::Params::new(20, 8, 8, 64)?;

        let mut result = [0u8; 64];
        scrypt::scrypt(pass.as_bytes(), salt.as_bytes(), &params, &mut result)?;
        let (half1, half2) = result.split_at_mut(32);
        half1.xor(&half2);

        Ok(half1.try_into().unwrap())
    }
}

trait Encryption: Derivation + Sized {
    /// Keep original words count
    fn encrypt(&self, passphrase: &str) -> Result<Self, EncError>;
    /// Decrypt encrypted nemonic
    fn decrypt(&self, passphrase: &str) -> Result<Self, EncError>;
}

impl Derivation for Mnemonic {}
impl Encryption for Mnemonic {
    fn encrypt(&self, passphrase: &str) -> Result<Self, EncError> {
        let mut secret_key = [0u8; 64];
        {
            let argon = argon2::Argon2::default();
            let pass: String = passphrase.nfc().collect();
            let salt = Self::passphrase_to_salt(passphrase)?;
            argon
                .hash_password_into(pass.as_bytes(), &salt, &mut secret_key)
                .map_err(|e| EncError::ArgonError(e))?;
        };
        let (mask, aes_key) = secret_key.split_at(32);

        let entropy = &mut self.entropy();
        entropy.resize(32, 0);
        entropy[..32].xor(&mask[..32]);
        let (part1, part2) = entropy.split_at_mut(16);

        let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
        cipher.encrypt_block(GenericArray::from_mut_slice(part1));
        if self.word_count() == 24 {
            cipher.encrypt_block(GenericArray::from_mut_slice(part2));
        }

        let out_bytes = self.word_count() / 3 * 4;
        Ok(Mnemonic::from_entropy(
            &entropy[..out_bytes],
            self.language(),
        )?)
    }

    fn decrypt(&self, passphrase: &str) -> Result<Self, EncError> {
        let mut secret_key = [0u8; 64];
        {
            let argon = argon2::Argon2::default();
            let pass: String = passphrase.nfc().collect();
            let salt = Self::passphrase_to_salt(passphrase)?;
            argon
                .hash_password_into(pass.as_bytes(), &salt, &mut secret_key)
                .map_err(|e| EncError::ArgonError(e))?;
        };
        let (mask, aes_key) = secret_key.split_at(32);

        let entropy = &mut self.entropy();
        entropy.resize(32, 0);
        let (part1, part2) = entropy.split_at_mut(16);

        let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
        cipher.decrypt_block(GenericArray::from_mut_slice(part1));
        if self.word_count() == 24 {
            cipher.decrypt_block(GenericArray::from_mut_slice(part2));
        }
        entropy[..32].xor(&mask[..32]);

        let out_bytes = self.word_count() / 3 * 4;
        Ok(Mnemonic::from_entropy(
            &entropy[..out_bytes],
            self.language(),
        )?)
    }
}

pub trait MnemonicEncryption {
    fn mnemonic_encrypt<const N: usize>(&self, passphrase: &str) -> Result<String, EncError>;
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError>;
}

impl MnemonicEncryption for str {
    fn mnemonic_encrypt<const N: usize>(&self, passphrase: &str) -> Result<String, EncError> {
        let mnemonic: Mnemonic = self.parse()?;
        if !matches!(N, 12 | 15 | 18 | 21 | 24 | 25) || N < mnemonic.word_count() {
            return Err(EncError::InvalidWordCount(N));
        }

        if N > mnemonic.word_count() {
            // Random salt.
        } else {
            // No random salt.
        }
        // let pass: String = passphrase.nfc().collect();
        Ok(String::new())
    }

    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, EncError> {
        todo!("Implement mnemonic decryption logic here");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EncError {
    #[error("Invalid word count: {0}")]
    InvalidWordCount(usize),
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::bip39::MnemonicError),
    #[error("Argon error: {0}")]
    ArgonError(argon2::Error),

    #[error("Scrypt error: {0}")]
    ScryptParam(#[from] scrypt::errors::InvalidParams),
    #[error("Scrypt error: {0}")]
    ScryptOutput(#[from] scrypt::errors::InvalidOutputLen),
}

trait ByteOperation {
    fn sha256_n(&self, n: usize) -> [u8; 32];
    fn xor(&mut self, other: &Self);
    fn segments<const N: usize>(&self, len_list: [usize; N]) -> [&[u8]; N];
    fn segments_mut<const N: usize>(&mut self, len_list: [usize; N]) -> [&mut [u8]; N];
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

    #[inline]
    fn segments<const N: usize>(&self, len_list: [usize; N]) -> [&[u8]; N] {
        let mut start = 0;
        let mut segments = [&self[..0]; N];
        for (i, &len) in len_list.iter().enumerate() {
            segments[i] = &self[start..start + len];
            start += len;
        }
        segments
    }

    #[inline]
    fn segments_mut<const N: usize>(&mut self, lens: [usize; N]) -> [&mut [u8]; N] {
        let mut segments = vec![];
        let mut rest = self;
        for len in lens {
            let (part1, part2) = rest.split_at_mut(len);
            segments.push(part1);
            rest = part2;
        }
        segments.try_into().unwrap()
    }
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
    fn test_passphrase_salt() {
        let now = std::time::Instant::now();
        let salt = Mnemonic::passphrase_to_salt("123456").unwrap();
        let seconds = (std::time::Instant::now() - now).as_secs_f32();
        println!("salt: {:X?}", salt);
        println!("Salt generation took: {:.2} seconds", seconds);
    }

    #[test]
    fn test_mnemonic_encrypt() {
        const TEST_DATA: &[&str] = &[
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音",
        ];
        for data in TEST_DATA.chunks(2) {
            let original = Mnemonic::from_str(data[0]).unwrap();
            let encrypted = Mnemonic::from_str(data[1]).unwrap();

            assert_eq!(original.encrypt("123456").unwrap(), encrypted);
            assert_eq!(encrypted.decrypt("123456").unwrap(), original);
        }
    }
}
