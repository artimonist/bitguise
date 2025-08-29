use super::Error;
use crate::{Mnemonic, Verify};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use unicode_normalization::UnicodeNormalization;

const DEFAULT_SALT: &str = "Thanks Satoshi!";

const DEFAULT_DERIVE_PATH: &str = "m/0'/0'";

type Result<T = ()> = std::result::Result<T, super::Error>;

pub trait MnemonicEncryption {
    fn default_address(&self) -> Result<String>;

    fn encrypt_extend(&self, password: &str, to_size: usize) -> Result<Mnemonic>;
    fn encrypt_random(&self, password: &str, to_size: usize) -> Result<Mnemonic>;
    fn decrypt_extend<T>(&self, password: &str, verify: T) -> Result<Mnemonic>
    where
        T: TryInto<Verify>;

    fn encrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>;

    fn decrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>;
}

impl MnemonicEncryption for Mnemonic {
    fn default_address(&self) -> Result<String> {
        default_address(self)
    }

    fn encrypt_extend(&self, password: &str, to_size: usize) -> Result<Mnemonic> {
        if to_size < self.size() || !Mnemonic::valid_size(to_size) {
            return Err(super::Error::InvalidSize);
        }

        let pwd = password.nfc().to_string();
        let salt = {
            let salt_len = (to_size - self.size()) / 3 * 4;
            let address_hash = default_address(self)?.as_bytes().sha256_n(1);
            address_hash[..salt_len].to_vec()
        };
        let secret_key = derive_secret_key(pwd.as_bytes(), &salt)?;

        let mut entropy = mnemonic_encrypt(self, &secret_key)?.entropy();
        entropy.extend_from_slice(&salt);
        Ok(Mnemonic::new(&entropy, self.language())?)
    }

    fn encrypt_random(&self, password: &str, to_size: usize) -> Result<Mnemonic> {
        if to_size < self.size() || !Mnemonic::valid_size(to_size) {
            return Err(super::Error::InvalidSize);
        }

        let pwd = password.nfc().to_string();
        let salt: Vec<u8> = {
            let len = (to_size - self.size()) / 3 * 4;
            (0..len).map(|_| rand::random()).collect()
        };
        let secret_key = derive_secret_key(pwd.as_bytes(), &salt)?;

        let mut entropy = mnemonic_encrypt(self, &secret_key)?.entropy();
        entropy.extend_from_slice(&salt);
        Ok(Mnemonic::new(&entropy, self.language())?)
    }

    fn decrypt_extend<T>(&self, password: &str, verify: T) -> Result<Mnemonic>
    where
        T: TryInto<Verify>,
    {
        let verify: Verify = verify.try_into().map_err(|_| Error::InvalidVerify)?;
        if verify.desired_size() > self.size() {
            return Err(super::Error::InvalidSize);
        }

        let pwd = password.nfc().to_string();
        let entropy_salt = self.entropy();
        let (entropy, salt) = entropy_salt.split_at(verify.desired_bytes());
        let secret_key = derive_secret_key(pwd.as_bytes(), &salt)?;

        let mnemonic = Mnemonic::new(entropy, self.language())?;
        let original = mnemonic_decrypt(&mnemonic, &secret_key)?;
        verify.check_mnemonic(&original)?;
        Ok(original)
    }

    fn encrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>,
    {
        let hash_pwds = (0..path.len())
            .map(|i| hash_password(path, i))
            .collect::<Vec<_>>();

        let mut mnemonic = self.clone();
        (0..path.len() - 1).map(move |i| {
            let pwd = hash_pwds[i];
            let salt = hash_pwds[i + 1];
            if let Ok(key) = derive_secret_key(&pwd, &salt)
                && let Ok(new_mnemonic) = mnemonic_encrypt(&mnemonic, &key)
            {
                mnemonic = new_mnemonic;
                Ok(mnemonic.clone())
            } else {
                Err(super::Error::EncryptError("Failed to encrypt".into()))
            }
        })
    }

    fn decrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>,
    {
        let hash_pwds = (0..path.len())
            .map(|i| hash_password(path, i))
            .collect::<Vec<_>>();

        let mut mnemonic = self.clone();
        (0..path.len() - 1).rev().map(move |i| {
            let pwd = hash_pwds[i];
            let salt = hash_pwds[i + 1];
            if let Ok(key) = derive_secret_key(&pwd, &salt)
                && let Ok(new_mnemonic) = mnemonic_decrypt(&mnemonic, &key)
            {
                mnemonic = new_mnemonic;
                Ok(mnemonic.clone())
            } else {
                Err(super::Error::EncryptError("Failed to decrypt".into()))
            }
        })
    }
}

/// Hash the password by SHA256, excluding the element at the given index
fn hash_password<S>(path: &[S], index: usize) -> [u8; 32]
where
    S: AsRef<str>,
{
    let times = 2_u32.pow(path.len() as u32);
    path.iter()
        .enumerate()
        .filter_map(move |(i, s)| if i != index { Some(s.as_ref()) } else { None })
        .collect::<Vec<_>>()
        .join("-")
        .as_bytes()
        .sha256_n(times as usize)
}

/// Derive a 64-byte secret key from the password and salt using Scrypt and Argon2
fn derive_secret_key(pwd: &[u8], salt: &[u8]) -> Result<[u8; 64]> {
    let argon_salt = {
        let mut result = [0u8; 64];
        let scrypt_salt = [DEFAULT_SALT.as_bytes(), salt].concat();
        let params = scrypt::Params::new(20, 8, 8, 64)?;
        scrypt::scrypt(pwd, &scrypt_salt, &params, &mut result)?;

        let (half1, half2) = result.split_at_mut(32);
        half1[..32].xor(&half2[..32]);
        half1[..32].to_vec()
    };
    let argon = argon2::Argon2::default();
    let mut secret_key = [0u8; 64];
    argon.hash_password_into(pwd, &argon_salt, &mut secret_key)?;
    Ok(secret_key)
}

/// Derive a Bitcoin address from the mnemonic and derivation path.
fn default_address(mnemonic: &Mnemonic) -> Result<String> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::{Address, Network, secp256k1::Secp256k1};
    use pbkdf2::pbkdf2_hmac;

    let seed = {
        let mnemonic = mnemonic.to_string();
        let salt = format!("mnemonic{}", DEFAULT_SALT).into_bytes();
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), &salt, u32::pow(2, 11), &mut seed);
        seed
    };
    let root = Xpriv::new_master(Network::Bitcoin, &seed)?;

    let address = {
        let derive_path: DerivationPath = DEFAULT_DERIVE_PATH.parse()?;
        let xpriv = root.derive_priv(&Secp256k1::default(), &derive_path)?;
        let pub_key = xpriv.to_priv().public_key(&Secp256k1::default());
        Address::p2pkh(pub_key, Network::Bitcoin).to_string()
    };
    Ok(address)
}

/// Encrypt the mnemonic using the given secret key
fn mnemonic_encrypt(original: &Mnemonic, secret_key: &[u8; 64]) -> Result<Mnemonic> {
    let (mask, aes_key) = secret_key.split_at(32);
    let entropy = &mut original.entropy();
    {
        entropy.resize(32, 0);
        entropy[..32].xor(&mask[..32]);
        let (part1, part2) = entropy.split_at_mut(16);

        let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
        cipher.encrypt_block(GenericArray::from_mut_slice(part1));
        if original.size() == 24 {
            cipher.encrypt_block(GenericArray::from_mut_slice(part2));
        }
        entropy.resize(original.size() / 3 * 4, 0);
    }
    let mnemonic = Mnemonic::new(entropy, original.language())?;
    Ok(mnemonic)
}

/// Decrypt the mnemonic using the given secret key
fn mnemonic_decrypt(mnemonic: &Mnemonic, secret_key: &[u8; 64]) -> Result<Mnemonic> {
    let (mask, aes_key) = secret_key.split_at(32);
    let entropy = &mut mnemonic.entropy();
    {
        entropy.resize(32, 0);
        let (part1, part2) = entropy.split_at_mut(16);

        let cipher = aes::Aes256::new(GenericArray::from_slice(aes_key));
        cipher.decrypt_block(GenericArray::from_mut_slice(part1));
        if mnemonic.size() == 24 {
            cipher.decrypt_block(GenericArray::from_mut_slice(part2));
        }
        entropy[..32].xor(&mask[..32]);
        entropy.resize(mnemonic.size() / 3 * 4, 0);
    }
    let mnemonic = Mnemonic::new(entropy, mnemonic.language())?;
    Ok(mnemonic)
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
    fn test_mnemonic_fix() {
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let encrypted = "坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音; 胞";

        let original: Mnemonic = original.parse().unwrap();
        let (encrypted, _) = Verify::parse(encrypted).unwrap();

        let mnemonic = original.encrypt_extend("123456", original.size()).unwrap();
        assert_eq!(mnemonic.to_string(), encrypted.to_string());
        // let mnemonic = encrypted.decrypt_extend("123456", verify).unwrap();
        // assert_eq!(mnemonic.to_string(), original.to_string());
    }

    #[test]
    fn test_mnemonic_full() {
        let data = [
            "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因",
            "件 指 坯 常 尸 湖 武 矿 床 平 偶 氧 展 刮 腐 差 驻 沫 梦 季 仪 馏 条 有; 各",
        ];
        let original: Mnemonic = data[0].parse().unwrap();
        let (encrypted, _) = Verify::parse(data[1]).unwrap();

        let mnemonic = original.encrypt_extend("123456", original.size()).unwrap();
        assert_eq!(mnemonic.to_string(), encrypted.to_string());
        let mnemonic = encrypted.decrypt_extend("123456", original.size()).unwrap();
        assert_eq!(mnemonic, original);
    }

    #[test]
    fn test_mnemonic_extend() {
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let encrypted = "抗 鲜 发 赤 外 盗 烂 璃 碰 者 美 姓 捕 阴 莫 礼 下 病; 胞";

        let original: Mnemonic = original.parse().unwrap();
        let (encrypted, _) = Verify::parse(encrypted).unwrap();

        let mnemonic = original.encrypt_extend("123456", 18).unwrap();
        assert_eq!(mnemonic.to_string(), encrypted.to_string());
        let mnemonic = encrypted.decrypt_extend("123456", original.size()).unwrap();
        assert_eq!(mnemonic, original);
    }

    #[test]
    fn test_mnemonic_random() {
        let original = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let original: Mnemonic = original.parse().unwrap();
        let v = Verify::from_mnemonic(&original).unwrap();

        let encrypted = original.encrypt_random("123456", 24).unwrap();
        assert_eq!(encrypted.decrypt_extend("123456", v).unwrap(), original);
        println!("Random encrypted: {encrypted}");
    }

    #[test]
    fn test_path_encrypt() -> Result {
        let original: Mnemonic = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔".parse()?;
        let path = vec!["1", "2", "3"];
        let encrypted = [
            "旗 改 跳 码 亲 我 姜 售 浅 舒 此 总 之 还 诺",
            "像 寺 识 晓 采 流 损 测 贷 姓 撞 人 径 以 氨",
        ];

        let mut mnemonic = original.clone();
        for (i, res) in original.encrypt_by_path(&path).enumerate() {
            mnemonic = res?;
            println!("Encrypted: {mnemonic}");
            assert_eq!(mnemonic.to_string(), encrypted[i]);
        }
        println!("Final Encrypted: {mnemonic}");
        Ok(())
    }

    #[test]
    fn test_path_decrypt() -> Result {
        let mnemonic: Mnemonic = "像 寺 识 晓 采 流 损 测 贷 姓 撞 人 径 以 氨".parse()?;
        let path = vec!["1", "2", "3"];
        let decrypted = [
            "旗 改 跳 码 亲 我 姜 售 浅 舒 此 总 之 还 诺",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
        ];

        let mut original = mnemonic.clone();
        for (i, res) in mnemonic.decrypt_by_path(&path).enumerate() {
            original = res?;
            println!("Encrypted: {original}");
            assert_eq!(original.to_string(), decrypted[i]);
        }
        println!("Final Decrypted: {original}");
        Ok(())
    }
}
