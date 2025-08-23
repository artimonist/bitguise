use crate::bip39::Mnemonic;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

const DEFAULT_SALT: &str = "Thanks Satoshi!";
const DERIVE_PATH: &str = "m/0'/0'";

#[derive(Debug)]
pub(crate) struct MnemonicEx {
    pub mnemonic: Mnemonic,
    pub verify: Verify,
}

#[derive(Debug)]
pub(crate) enum Verify {
    Word(usize), // Mnemonic size (3 bits) and derivation address (m/0'/0') hash (8 bits).
    Size(u8),    // Mnemonic encrypt or decrypt desired size.
}

impl MnemonicEx {
    pub fn desired_size(&self) -> usize {
        match self.verify {
            Verify::Word(i) => (8 - (i >> 8)) * 3,
            Verify::Size(n) => n as usize,
        }
    }
    pub fn verify_sum(&self) -> Option<u8> {
        match self.verify {
            Verify::Word(i) => Some((i & 0xff) as u8),
            Verify::Size(_) => None,
        }
    }
    pub fn verify_word(&self) -> Option<&str> {
        match self.verify {
            Verify::Word(i) => self.mnemonic.language().word_at(i),
            Verify::Size(_) => None,
        }
    }
}

impl std::ops::Deref for MnemonicEx {
    type Target = Mnemonic;

    fn deref(&self) -> &Self::Target {
        &self.mnemonic
    }
}

impl From<Mnemonic> for MnemonicEx {
    fn from(mnemonic: Mnemonic) -> Self {
        // Todo: Generate verify word
        let verify = Verify::Size(mnemonic.size() as u8);
        Self { mnemonic, verify }
    }
}

impl std::fmt::Display for MnemonicEx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mnemonic)?;
        match self.verify {
            Verify::Word(i) => {
                if let Some(w) = self.language().word_at(i) {
                    write!(f, "; {w}")?;
                }
            }
            Verify::Size(n) => {
                if n as usize != self.size() {
                    write!(f, "; {n}")?;
                }
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for MnemonicEx {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let count = s.split_whitespace().count();
        if matches!(count, 12 | 15 | 18 | 21 | 24) {
            // none verify word
            return Ok(s.parse::<Mnemonic>()?.into());
        }
        // has verify word or desired count
        let Some((mnemonic_str, verify_str)) = s.rsplit_once(' ') else {
            return Err(Error::InvalidKey);
        };
        let mnemonic: Mnemonic = mnemonic_str.trim_end_matches(';').parse()?;

        let verify = if let Some(i) = mnemonic.language().index_of(verify_str)
            && i >> 8 < 5
        {
            // valid verify word
            Verify::Word(i)
        } else if let Ok(n) = verify_str.parse::<u8>()
            && matches!(n, 12 | 15 | 18 | 21 | 24)
        {
            // desired word count
            Verify::Size(n)
        } else {
            return Err(Error::InvalidKey);
        };
        Ok(Self { mnemonic, verify })
    }
}

pub(crate) trait Derivation {
    /// Derive a secret key from the passphrase and salt.
    fn derive_secret_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 64], Error> {
        let pass: String = passphrase.nfc().collect();
        let argon_salt = {
            let scrypt_salt = [DEFAULT_SALT.as_bytes(), salt].concat();
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

    /// Derive a Bitcoin address from the mnemonic and derivation path.
    fn derive_path_address(mnemonic: &Mnemonic, path: &str) -> Result<String, Error> {
        use bitcoin::bip32::{DerivationPath, Xpriv};
        use bitcoin::{Address, Network, secp256k1::Secp256k1};
        use pbkdf2::pbkdf2_hmac;

        let seed = {
            let mnemonic = mnemonic.to_string();
            let salt = format!("mnemonic{DEFAULT_SALT}").into_bytes();
            let mut seed = [0u8; 64];
            pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), &salt, u32::pow(2, 11), &mut seed);
            seed
        };
        let root = Xpriv::new_master(Network::Bitcoin, &seed)?;

        let address = {
            let derive_path: DerivationPath = path.parse()?;
            let xpriv = root.derive_priv(&Secp256k1::default(), &derive_path)?;
            let pub_key = xpriv.to_priv().public_key(&Secp256k1::default());
            Address::p2pkh(&pub_key, Network::Bitcoin).to_string()
        };
        Ok(address)
    }
}

pub(crate) trait Encryption: Derivation + Sized {
    /// Encrypt the mnemonic with a passphrase and salt,
    ///   returning the new mnemonic and a verify word.
    /// The salt is used to extend the mnemonic length,
    ///   and the verify word is used to verify the decryption.
    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<Self, Error>;

    /// Decrypt the mnemonic with a passphrase and verify word, returning the original mnemonic.
    /// If the verify word is empty, it will ignore the checksum.
    /// The verify word can be a word from the mnemonic language
    ///   or a count in the format "12", "15", "18", "21", or "24".
    fn decrypt_extend(&self, passphrase: &str) -> Result<Self, Error>;
}

impl Derivation for MnemonicEx {}
impl Encryption for MnemonicEx {
    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<Self, Error> {
        let result_bytes = self.size() / 3 * 4 + salt.len();
        assert!(matches!(result_bytes, 16 | 20 | 24 | 28 | 32));

        let secret_key = Self::derive_secret_key(passphrase, salt)?;
        let (mask, aes_key) = secret_key.split_at(32);

        let entropy = &mut self.entropy();
        {
            entropy.resize(32, 0);
            entropy[..32].xor(&mask[..32]);
            let (part1, part2) = entropy.split_at_mut(16);

            let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
            cipher.encrypt_block(GenericArray::from_mut_slice(part1));
            if self.size() == 24 {
                cipher.encrypt_block(GenericArray::from_mut_slice(part2));
            }

            entropy.resize(self.size() / 3 * 4, 0);
            entropy.extend_from_slice(salt);
        }

        let mnemonic = Mnemonic::from_entropy(entropy, self.language())?;
        let verify = {
            let address = Self::derive_path_address(&self, DERIVE_PATH)?;
            let checksum: u16 = address.as_bytes().sha256_n(2)[0] as u16;
            let size_flag: u16 = 8 - (self.size() as u16 / 3); // 4 | 3 | 2 | 1 | 0
            assert!(size_flag < 5);
            let index = (size_flag << 8 | checksum) as usize;
            Verify::Word(index)
        };
        Ok(MnemonicEx { mnemonic, verify })
    }

    fn decrypt_extend(&self, passphrase: &str) -> Result<Self, Error> {
        let result_bytes = self.desired_size() / 3 * 4;
        assert!(matches!(result_bytes, 16 | 20 | 24 | 28 | 32));

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

        if let Some(checksum) = self.verify_sum() {
            let address = Self::derive_path_address(&original, DERIVE_PATH)?;
            if checksum != address.as_bytes().sha256_n(2)[0] {
                return Err(Error::InvalidPass);
            }
        }
        Ok(original.into())
    }
}

pub trait MnemonicEncryption {
    /// Encrypt the mnemonic with a passphrase and desired word count.
    /// The word count must be one of 12, 15, 18, 21, or 24.
    /// The mnemonic will be extended with random words to match the desired count.
    /// Returns the new mnemonic and a verify word for decryption.
    fn mnemonic_encrypt(&self, passphrase: &str) -> Result<String, Error>;

    /// Decrypt the mnemonic with a passphrase.
    /// If the mnemonic is encrypted with a verify word, it will be used to verify the decryption.
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, Error>;
}
impl MnemonicEncryption for str {
    /// Encrypt the mnemonic with a passphrase and desired word count.
    fn mnemonic_encrypt(&self, passphrase: &str) -> Result<String, Error> {
        let original: MnemonicEx = self.parse()?;
        if original.desired_size() < original.size() {
            return Err(Error::InvalidSize);
        }

        // Generate a random salt if the desired size is greater than the original.
        // The salt will be used to extend the mnemonic length.
        let salt = &mut vec![0u8; (original.desired_size() - original.size()) / 3 * 4];
        if !salt.is_empty() {
            rand::thread_rng().fill_bytes(salt);
        }

        let mnemonic = original.encrypt_extend(passphrase, salt)?;
        Ok(mnemonic.to_string())
    }

    /// Decrypt the mnemonic with a passphrase.
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String, Error> {
        let mnemonic: MnemonicEx = self.parse()?;
        if mnemonic.desired_size() > mnemonic.size() {
            return Err(Error::InvalidSize);
        }
        let original = mnemonic.decrypt_extend(passphrase)?;
        Ok(original.to_string())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid count")]
    InvalidSize,
    #[error("Invalid passphrase")]
    InvalidPass,
    #[error("Encrypt error: {0}")]
    EncryptError(String),
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::MnemonicError),
}

macro_rules! derive_error {
    ($e:expr, $source:ty) => {
        impl From<$source> for Error {
            fn from(e: $source) -> Self {
                $e(e.to_string())
            }
        }
    };
}
derive_error!(Error::EncryptError, argon2::Error);
derive_error!(Error::EncryptError, scrypt::errors::InvalidOutputLen);
derive_error!(Error::EncryptError, scrypt::errors::InvalidParams);
derive_error!(Error::EncryptError, bitcoin::bip32::Error);

pub trait ByteOperation {
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
        assert!(self.len() == other.len());
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
            "坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音; 胞",
        ];
        for data in TEST_DATA.chunks(2) {
            assert_eq!(data[0].mnemonic_encrypt("123456").unwrap(), data[1]);
            assert_eq!(data[1].mnemonic_decrypt("123456").unwrap(), data[0]);

            let mnemonic = data[1].rsplit_once(';').unwrap().0;
            assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), data[0]);
            let mnemonic = data[1].replace(';', "");
            assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), data[0]);
        }
    }

    #[test]
    fn test_mnemonic_extend() {
        let data = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let encrypted = format!("{data}; 24").mnemonic_encrypt("123456").unwrap();
        assert_eq!(encrypted.mnemonic_decrypt("123456").unwrap(), data);

        let mnemonic = format!("{}; 15", encrypted.rsplit_once(';').unwrap().0);
        assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), data);
        println!("Encrypted: {encrypted}");
    }

    #[test]
    fn test_mnemonic_full() {
        let original = "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因";
        let encrypted = original.mnemonic_encrypt("123456").unwrap();
        assert_eq!(encrypted.mnemonic_decrypt("123456").unwrap(), original);
        println!("Encrypted: {encrypted}");
    }
}
