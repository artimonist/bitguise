use crate::{Mnemonic, encrypt::mnemonic::ByteOperation};
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

type Result<T> = std::result::Result<T, super::Error>;

pub trait HashPassword {
    fn hash_password(&self, index: usize) -> [u8; 32];
}

impl<S> HashPassword for [S]
where
    S: AsRef<str>,
{
    // Generate passwords by excluding one segment at a time
    fn hash_password(&self, index: usize) -> [u8; 32] {
        let times = 2_u32.pow(self.len() as u32);
        self.iter()
            .enumerate()
            .filter_map(move |(i, s)| if i != index { Some(s.as_ref()) } else { None })
            .collect::<Vec<_>>()
            .join("-")
            .as_bytes()
            .sha256_n(times as usize)
    }
}

pub trait PathEncryption {
    fn path_encrypt(&self, original: &Mnemonic) -> impl Iterator<Item = Result<Mnemonic>>;
}

impl<S> PathEncryption for [S]
where
    S: AsRef<str>,
{
    fn path_encrypt(&self, original: &Mnemonic) -> impl Iterator<Item = Result<Mnemonic>> {
        let hash_pwds = (0..self.len())
            .map(|i| self.hash_password(i))
            .collect::<Vec<_>>();

        let mut mnemonic = original.clone();
        (0..self.len() - 1).map(move |i| {
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
}

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

    let mnemonic = Mnemonic::from_entropy(entropy, original.language())?;
    Ok(mnemonic)
}
