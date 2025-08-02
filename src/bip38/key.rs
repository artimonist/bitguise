use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use bitcoin::{Address, NetworkKind, PrivateKey, base58, secp256k1::Secp256k1};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

/// BIP38 trait for encrypting and decrypting private keys.
/// # Reference
///  [Definition](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
///  [Description](https://blockcoach.com/2023/202306/2023-06-20-A-BIP38/)
///  [Implementation](https://github.com/ceca69ec/bip38)
pub trait Bip38 {
    fn encrypt_non_ec(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<PrivateKey, Bip38Error>;

    /// Generates a 64-byte pass factor for EC multiplication.
    /// # Arguments
    /// * `passphrase` - The passphrase used to derive the key.
    /// * `lot` - The lot number, which should be between 100000 and 999999.
    /// * `seq` - The sequence number, which should be between 1 and 4095.
    /// * if `lot` and `seq` are both zero, a random salt is generated.
    /// # Reference
    /// > The "lot" and "sequence" number are combined into a single 32 bit number.
    /// > 20 bits are used for the lot number and 12 bits are used for the sequence number,
    /// > such that the lot number can be any decimal number between 0 and 1048575,
    /// > and the sequence number can be any decimal number between 0 and 4095.
    /// > For programs that generate batches of intermediate codes for an owner,
    /// > it is recommended that lot numbers be chosen at random within the range 100000-999999
    /// > and that sequence numbers are assigned starting with 1.
    fn generate_ec_pass(passphrase: &str, lot: u32, seq: u32) -> Result<String, Bip38Error>;
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

    fn generate_ec_pass(passphrase: &str, lot: u32, seq: u32) -> Result<String, Bip38Error> {
        match (lot, seq) {
            (100000..=999999, 1..=4095) => {
                let salt: [u8; 4] = rand::thread_rng().next_u32().to_be_bytes();
                let mut entropy: [u8; 8] = [0; 8];
                entropy[..4].copy_from_slice(&salt);
                entropy[4..].copy_from_slice(&(lot << 12 | seq).to_be_bytes());

                let pass_factor = {
                    let pass = passphrase.nfc().collect::<String>();
                    let params = scrypt::Params::new(14, 8, 8, 32)?;
                    let mut pre_factor = [0u8; 32];
                    scrypt::scrypt(pass.as_bytes(), &salt, &params, &mut pre_factor)?;

                    [&pre_factor[..32], &entropy[..8]].concat().sha256_n(2)
                };
                let pass_point = PrivateKey::from_slice(&pass_factor, NetworkKind::Main)?
                    .public_key(&Secp256k1::default())
                    .to_bytes();
                debug_assert_eq!(pass_point.len(), 33);

                let ec_pass = [
                    &[0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51][..8],
                    &entropy[..8],
                    &pass_point[..33],
                ]
                .concat();
                Ok(base58::encode_check(&ec_pass))
            }
            (0, 0) => {
                let entropy: [u8; 8] = rand::thread_rng().next_u64().to_be_bytes();
                let mut pass_factor = [0u8; 32];
                {
                    let pass = passphrase.nfc().collect::<String>();
                    let params = scrypt::Params::new(14, 8, 8, 32)?;
                    scrypt::scrypt(pass.as_bytes(), &entropy, &params, &mut pass_factor)?;
                }
                let pass_point = PrivateKey::from_slice(&pass_factor, NetworkKind::Main)?
                    .public_key(&Secp256k1::default())
                    .to_bytes();
                debug_assert_eq!(pass_point.len(), 33);

                let ec_pass: Vec<u8> = [
                    &[0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53][..8],
                    &entropy[..8],
                    &pass_point[..33],
                ]
                .concat();
                Ok(base58::encode_check(&ec_pass))
            }
            _ => {
                return Err(Bip38Error::InvalidEcNumber(lot as u32, seq as u32));
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Bip38Error {
    #[error("Invalid BIP38 encrypted key")]
    InvalidKey,
    #[error("Invalid passphrase or checksum mismatch")]
    InvalidChecksum,
    #[error("Invalid lot or sequence number: lot: {0}, seq: {1}")]
    InvalidEcNumber(u32, u32),
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
