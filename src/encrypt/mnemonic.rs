use super::Error;
use crate::{bip39::Mnemonic, encrypt::verify::Verify};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use unicode_normalization::UnicodeNormalization;

type Result<T = ()> = std::result::Result<T, super::Error>;

pub trait MnemonicExtension: Sized {
    const DEFAULT_SALT: &str = "Thanks Satoshi!";
    const DERIVE_PATH: &str = "m/0'/0'";

    /// Derive a secret key from the passphrase and salt.
    fn derive_secret_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 64]> {
        let pass: String = passphrase.nfc().collect();
        let argon_salt = {
            let scrypt_salt = [Self::DEFAULT_SALT.as_bytes(), salt].concat();
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
    fn derive_path_address(mnemonic: &Mnemonic, path: &str) -> Result<String> {
        use bitcoin::bip32::{DerivationPath, Xpriv};
        use bitcoin::{Address, Network, secp256k1::Secp256k1};
        use pbkdf2::pbkdf2_hmac;

        let seed = {
            let mnemonic = mnemonic.to_string();
            let salt = format!("mnemonic{}", Self::DEFAULT_SALT).into_bytes();
            let mut seed = [0u8; 64];
            pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), &salt, u32::pow(2, 11), &mut seed);
            seed
        };
        let root = Xpriv::new_master(Network::Bitcoin, &seed)?;

        let address = {
            let derive_path: DerivationPath = path.parse()?;
            let xpriv = root.derive_priv(&Secp256k1::default(), &derive_path)?;
            let pub_key = xpriv.to_priv().public_key(&Secp256k1::default());
            Address::p2pkh(pub_key, Network::Bitcoin).to_string()
        };
        Ok(address)
    }

    /// Derive a Bitcoin address from mnemonic by path `m/0'/0'`.
    fn default_address(&self) -> Result<String>;

    /// Encrypt the mnemonic with a passphrase and salt,
    ///   returning the new mnemonic and a verify word.
    /// The salt is used to extend the mnemonic length,
    ///   and the verify word is used to verify the decryption.
    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<Self>;

    /// Decrypt the mnemonic with a passphrase and verify word, returning the original mnemonic.
    /// If the verify word is empty, it will ignore the checksum.
    /// The verify word can be a word from the mnemonic language
    ///   or a count in the format "12", "15", "18", "21", or "24".
    fn decrypt_extend(&self, passphrase: &str, verify: &Verify) -> Result<Self>;
}

impl MnemonicExtension for Mnemonic {
    #[inline(always)]
    fn default_address(&self) -> Result<String> {
        Self::derive_path_address(self, Self::DERIVE_PATH)
    }

    fn encrypt_extend(&self, passphrase: &str, salt: &[u8]) -> Result<Self> {
        let desired_bytes = self.size() / 3 * 4 + salt.len();
        if !Mnemonic::valid_bytes(desired_bytes) {
            return Err(Error::InvalidSize);
        }

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

        let mnemonic = Mnemonic::new(entropy, self.language())?;
        Ok(mnemonic)
    }

    fn decrypt_extend(&self, passphrase: &str, verify: &Verify) -> Result<Self> {
        if verify.desired_size() > self.size() {
            return Err(Error::InvalidSize);
        }

        let desired_bytes = verify.desired_bytes();
        let entropy = &mut self.entropy();
        {
            let salt: Vec<_> = entropy.drain(desired_bytes..).collect();
            let secret_key = Self::derive_secret_key(passphrase, &salt)?;
            let (mask, aes_key) = secret_key.split_at(32);

            entropy.resize(32, 0);
            let (part1, part2) = entropy.split_at_mut(16);

            let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
            cipher.decrypt_block(GenericArray::from_mut_slice(part1));
            if desired_bytes == 32 {
                cipher.decrypt_block(GenericArray::from_mut_slice(part2));
            }
            entropy[..32].xor(&mask[..32]);
            entropy.resize(desired_bytes, 0);
        }

        let original = Mnemonic::new(entropy, self.language())?;
        if !verify.check_mnemonic(&original)? {
            return Err(Error::InvalidPass);
        }
        Ok(original)
    }
}

pub trait MnemonicEncryption {
    /// Encrypt the mnemonic with a passphrase and desired word count.
    /// The word count must be one of 12, 15, 18, 21, or 24.
    /// The mnemonic will be extended with address hash to match the desired count.
    /// Returns the new mnemonic and a verify word for decryption.
    fn mnemonic_encrypt(&self, passphrase: &str) -> Result<String>;

    /// Encrypt and extend the mnemonic with a passphrase and desired word count.
    /// The word count must be one of 12, 15, 18, 21, or 24 and greater than the original count.
    /// The mnemonic will be extended with random bytes to match the desired count.
    /// Returns the new mnemonic and a verify word for decryption.
    fn mnemonic_extend_random(&self, passphrase: &str) -> Result<String>;

    /// Decrypt the mnemonic with a passphrase.
    /// If the mnemonic is encrypted with a verify word, it will be used to verify the decryption.
    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String>;
}

impl MnemonicEncryption for str {
    fn mnemonic_encrypt(&self, passphrase: &str) -> Result<String> {
        let (original, verify) = Verify::parse(self)?;
        if verify.desired_size() < original.size() {
            return Err(Error::InvalidSize);
        }

        let salt = {
            let salt_len = (verify.desired_size() - original.size()) / 3 * 4;
            let address_hash = original.default_address()?.as_bytes().sha256_n(1);
            address_hash[..salt_len].to_vec()
        };

        let encrypted_mnemonic = original.encrypt_extend(passphrase, &salt)?;
        let original_verify = Verify::from_mnemonic(&original)?;
        Ok(format!("{encrypted_mnemonic}; {original_verify}"))
    }

    fn mnemonic_extend_random(&self, passphrase: &str) -> Result<String> {
        let (original, verify) = Verify::parse(self)?;
        if verify.desired_size() <= original.size() {
            return Err(Error::InvalidSize);
        }
        let salt = {
            let salt_len = (verify.desired_size() - original.size()) / 3 * 4;
            vec![rand::random(); salt_len]
        };

        let encrypted_mnemonic = original.encrypt_extend(passphrase, &salt)?;
        let original_verify = Verify::from_mnemonic(&original)?;
        Ok(format!("{encrypted_mnemonic}; {original_verify}"))
    }

    fn mnemonic_decrypt(&self, passphrase: &str) -> Result<String> {
        let (mnemonic, verify) = Verify::parse(self)?;
        if verify.desired_size() > mnemonic.size() {
            return Err(Error::InvalidSize);
        }
        let original = mnemonic.decrypt_extend(passphrase, &verify)?;
        Ok(format!("{original}"))
    }
}

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
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let encrypted = "坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音; 胞";
        let (x, y) = (original, encrypted);

        assert_eq!(x.mnemonic_encrypt("123456").unwrap(), y);
        assert_eq!(y.mnemonic_decrypt("123456").unwrap(), x);

        // no verify word, decrypt ok.
        let mnemonic = y.rsplit_once(';').unwrap().0;
        assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), x);

        // semicolon is necessary to partition off verify word.
        // let mnemonic = y.replace(';', "");
        // assert_eq!(mnemonic.mnemonic_decrypt("123456").unwrap(), x);
    }

    #[test]
    fn test_mnemonic_full() {
        let original = "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因";
        let encrypted =
            "件 指 坯 常 尸 湖 武 矿 床 平 偶 氧 展 刮 腐 差 驻 沫 梦 季 仪 馏 条 有; 各";

        assert_eq!(original.mnemonic_encrypt("123456").unwrap(), encrypted);
        assert_eq!(encrypted.mnemonic_decrypt("123456").unwrap(), original);
    }

    #[test]
    fn test_mnemonic_extend() {
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let encrypted = "抗 鲜 发 赤 外 盗 烂 璃 碰 者 美 姓 捕 阴 莫 礼 下 病; 胞";

        assert_eq!(
            format!("{original}; 18")
                .mnemonic_encrypt("123456")
                .unwrap(),
            encrypted
        );
        assert_eq!(encrypted.mnemonic_decrypt("123456").unwrap(), original);

        let desired = format!("{}; 15", encrypted.rsplit_once(';').unwrap().0);
        assert_eq!(desired.mnemonic_decrypt("123456").unwrap(), original);
    }

    #[test]
    fn test_mnemonic_random() {
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";

        let desired = format!("{original}; 24");
        let encrypted = desired.mnemonic_extend_random("123456").unwrap();
        assert_eq!(encrypted.mnemonic_decrypt("123456").unwrap(), original);
        println!("Encrypted: {encrypted}");
    }
}
