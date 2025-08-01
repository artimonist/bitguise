use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use bitcoin::{Address, NetworkKind, PrivateKey, base58, secp256k1::Secp256k1};
use unicode_normalization::UnicodeNormalization;

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// BIP38 trait for encrypting and decrypting private keys.
/// # Reference
///  [Definition](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
///  [Description](https://blockcoach.com/2023/202306/2023-06-20-A-BIP38/)
///  [Implementation](https://github.com/ceca69ec/bip38)
pub trait Bip38 {
    fn encrypt_non_ec(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<PrivateKey, Bip38Error>;
}

impl Bip38 for PrivateKey {
    fn encrypt_non_ec(&self, passphrase: &str) -> Result<String, Bip38Error> {
        let salt = {
            let pub_key = self.public_key(&Secp256k1::default());
            let address = Address::p2pkh(pub_key, NetworkKind::Main).to_string();
            address.as_bytes().sha256_n(2)[0..4].to_vec()
        };
        let mut scrypt_key = [0u8; 64];
        {
            let pass = passphrase.nfc().collect::<String>();
            let params = scrypt::Params::new(14, 8, 8, 64)?;
            scrypt::scrypt(pass.as_bytes(), &salt, &params, &mut scrypt_key)?;
        }
        let (part1, part2) = {
            let (half1, half2) = scrypt_key.split_at_mut(32);
            half1
                .iter_mut()
                .zip(self.to_bytes().iter())
                .for_each(|(x, y)| *x ^= y);
            let cipher = aes::Aes256::new_from_slice(half2)?;

            let (part1, part2) = half1.split_at_mut(16);
            cipher.encrypt_block(GenericArray::from_mut_slice(part1));
            cipher.encrypt_block(GenericArray::from_mut_slice(part2));

            (part1, part2)
        };

        let compress: [u8; 1] = if self.compressed { [0xe0] } else { [0xc0] };
        let buffer = [
            &PRE_NON_EC[..2],
            &compress[..1],
            &salt[..4],
            &part1[..16],
            &part2[..16],
        ]
        .concat();
        Ok(base58::encode_check(&buffer))
    }

    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<PrivateKey, Bip38Error> {
        let mut ebuffer = base58::decode_check(wif)?;
        if ebuffer.len() != 39 || ebuffer[..2] != PRE_NON_EC {
            return Err(Bip38Error::InvalidKey);
        }
        let compress = (ebuffer[2] & 0x20) == 0x20;
        let salt = &ebuffer[3..7].to_vec();
        let (part1, part2) = ebuffer[7..].split_at_mut(16);

        let mut scrypt_key = [0u8; 64];
        {
            let pass = passphrase.nfc().collect::<String>();
            let params = scrypt::Params::new(14, 8, 8, 64)?;
            scrypt::scrypt(pass.as_bytes(), salt, &params, &mut scrypt_key)?;
        };

        // Decrypt the two parts of the key
        let (half1, half2) = scrypt_key.split_at_mut(32);
        let cipher = aes::Aes256::new_from_slice(half2)?;
        cipher.decrypt_block(GenericArray::from_mut_slice(part1));
        cipher.decrypt_block(GenericArray::from_mut_slice(part2));

        // XOR the decrypted parts with the first half of the scrypt key
        half1
            .iter_mut()
            .zip(part1.iter().chain(part2.iter()))
            .for_each(|(x, y)| *x ^= y);

        let mut prvk = PrivateKey::from_slice(half1, NetworkKind::Main)?;
        prvk.compressed = compress;
        {
            // Verify the checksum
            let pub_key = prvk.public_key(&Secp256k1::default());
            let address = Address::p2pkh(pub_key, NetworkKind::Main).to_string();
            let checksum = address.as_bytes().sha256_n(2)[..4].to_vec();
            if checksum != *salt {
                return Err(Bip38Error::InvalidChecksum);
            }
        }
        Ok(prvk)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Bip38Error {
    #[error("Invalid BIP38 encrypted key")]
    InvalidKey,
    #[error("Invalid passphrase or checksum mismatch")]
    InvalidChecksum,
    #[error("Scrypt error: {0}")]
    ScryptOutput(#[from] scrypt::errors::InvalidOutputLen),
    #[error("Scrypt error: {0}")]
    ScryptParams(#[from] scrypt::errors::InvalidParams),
    #[error("AES error: {0}")]
    AesError(#[from] aes::cipher::InvalidLength),
    #[error("Base58 error: {0}")]
    Base58Error(#[from] bitcoin::base58::Error),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(#[from] bitcoin::secp256k1::Error),
}

trait Sha256N {
    fn sha256_n(&self, n: usize) -> [u8; 32];
}

impl Sha256N for [u8] {
    fn sha256_n(&self, n: usize) -> [u8; 32] {
        use bitcoin::{hashes::Hash, hashes::sha256};

        assert!(n > 0, "Cannot hash zero times");
        let mut hash = sha256::Hash::hash(self).to_byte_array();
        for _ in 1..n {
            hash = sha256::Hash::hash(&hash).to_byte_array();
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_ec() {
        const TEST_DATA: &[&str] = &[
            // No compression, no EC multiply
            "TestingOneTwoThree",
            "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
            "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
            "Satoshi",
            "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
            "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
            "ϓ\0𐐀💩",
            "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
            "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
            // Compression, no EC multiply
            "TestingOneTwoThree",
            "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
            "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
            "Satoshi",
            "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
            "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        ];

        use hex::FromHex;
        assert_eq!("ϓ\0𐐀💩", "\u{03D2}\u{0301}\u{0000}\u{010400}\u{01F4A9}");
        assert_eq!(
            "ϓ\0𐐀💩".nfc().collect::<String>().as_bytes(),
            Vec::from_hex("cf9300f0909080f09f92a9").unwrap()
        );

        for data in TEST_DATA.chunks(3) {
            let (pwd, enc_wif, wif) = (data[0], data[1], data[2]);

            let prvk = PrivateKey::from_wif(wif).expect("Failed to parse WIF");
            let encrypted = prvk.encrypt_non_ec(pwd).expect("Encryption failed");
            assert_eq!(encrypted, *enc_wif, "Encryption mismatch");

            let decrypted = PrivateKey::decrypt_non_ec(&encrypted, pwd).expect("Decryption failed");
            assert_eq!(decrypted.to_wif(), *wif, "Decryption mismatch");
        }
    }
}
