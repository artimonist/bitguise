use crate::{Mnemonic, encrypt::mnemonic::ByteOperation};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

type Result<T = ()> = std::result::Result<T, super::Error>;

pub trait PathEncryption {
    fn encrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>;

    fn decrypt_by_path<S>(&self, path: &[S]) -> impl Iterator<Item = Result<Mnemonic>>
    where
        S: AsRef<str>;
}

impl PathEncryption for Mnemonic {
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
        let params = scrypt::Params::new(20, 8, 8, 64)?;
        scrypt::scrypt(pwd, salt, &params, &mut result)?;

        let (half1, half2) = result.split_at_mut(32);
        half1[..32].xor(&half2[..32]);
        half1[..32].to_vec()
    };
    let argon = argon2::Argon2::default();
    let mut secret_key = [0u8; 64];
    argon.hash_password_into(pwd, &argon_salt, &mut secret_key)?;
    Ok(secret_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_encrypt() -> Result {
        let original: Mnemonic = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔".parse()?;
        let path = vec!["1", "2", "3"];
        let encrypted = [
            "贫 等 弟 迷 行 圣 巡 无 位 胡 艇 典 储 席 拌",
            "斤 厘 秒 伪 碰 场 少 肃 崇 优 辈 逮 背 该 屋",
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
        let mnemonic: Mnemonic = "斤 厘 秒 伪 碰 场 少 肃 崇 优 辈 逮 背 该 屋".parse()?;
        let path = vec!["1", "2", "3"];
        let decrypted = [
            "贫 等 弟 迷 行 圣 巡 无 位 胡 艇 典 储 席 拌",
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
