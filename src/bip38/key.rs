use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, base58};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

trait Bip38NonEc
where
    Self: Sized,
{
    /// Encrypts a non-EC private key using BIP38.
    fn encrypt_non_ec(&self, passphrase: &str) -> Result<String, Bip38Error>;

    /// Decrypts a non-EC private key using BIP38.
    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<Self, Bip38Error>;
}

impl Bip38NonEc for PrivateKey {
    fn encrypt_non_ec(&self, passphrase: &str) -> Result<String, Bip38Error> {
        let salt = self.p2pkh()?.as_bytes().sha256_n(2)[0..4].to_vec();
        let mut scrypt_key = [0u8; 64];
        {
            let pass = passphrase.nfc().collect::<String>();
            let params = scrypt::Params::new(14, 8, 8, 64)?;
            scrypt::scrypt(pass.as_bytes(), &salt, &params, &mut scrypt_key)?;
        }
        let (part1, part2) = {
            let (half1, half2) = scrypt_key.split_at_mut(32);
            half1[..32].xor(&self.to_bytes()[..32]);
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

    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<Self, Bip38Error> {
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
        half1[..16].xor(&part1[..16]);
        half1[16..32].xor(&part2[..16]);

        let mut prvk = PrivateKey::from_slice(half1, NetworkKind::Main)?;
        prvk.compressed = compress;

        // Verify the checksum
        if *salt != prvk.p2pkh()?.as_bytes().sha256_n(2)[..4] {
            return Err(Bip38Error::InvalidPassphrase);
        }
        Ok(prvk)
    }
}

struct EcMultiply;

impl EcMultiply {
    /// EC_PASS has "lot" and "sequence".
    const PRE_EC_PASS_SEQ: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];

    /// EC_PASS not has "lot" and "sequence".
    const PRE_EC_PASS_NON: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53];

    fn generate_ec_pass(
        passphrase: &str,
        salt: [u8; 8],
        lot: u32,
        seq: u32,
    ) -> Result<String, Bip38Error> {
        match (lot, seq) {
            (100000..=999999, 1..=4095) => {
                let salt = salt[..4].to_vec();

                let mut entropy: [u8; 8] = [0; 8];
                entropy[..4].copy_from_slice(&salt[..4]);
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
                    &Self::PRE_EC_PASS_SEQ[..8],
                    &entropy[..8],
                    &pass_point[..33],
                ]
                .concat();
                Ok(base58::encode_check(&ec_pass))
            }
            (0, 0) => {
                let entropy: [u8; 8] = salt;
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
                    &Self::PRE_EC_PASS_NON[..8],
                    &entropy[..8],
                    &pass_point[..33],
                ]
                .concat();
                Ok(base58::encode_check(&ec_pass))
            }
            _ => Err(Bip38Error::InvalidEcNumber(lot, seq)),
        }
    }

    fn generate_ec_key(seed: [u8; 24], ec_pass: &str) -> Result<String, Bip38Error> {
        let compressed = true;
        let ec_pass = base58::decode_check(ec_pass)?;
        let lot_seq = match &ec_pass[..8] {
            v if v == Self::PRE_EC_PASS_SEQ => true,
            v if v == Self::PRE_EC_PASS_NON => false,
            _ => return Err(Bip38Error::InvalidEcFactor),
        };
        let entropy = &ec_pass[8..16];
        let pass_point = &ec_pass[16..49];

        let factor = seed.sha256_n(2);
        let address_hash = {
            let secp_pub = secp256k1::PublicKey::from_slice(pass_point)?.mul_tweak(
                &Secp256k1::default(),
                &secp256k1::Scalar::from_be_bytes(factor)?,
            )?;
            let addr = Address::p2pkh(CompressedPublicKey(secp_pub), Network::Bitcoin).to_string();
            addr.as_bytes().sha256_n(2)[0..4].to_vec()
        };

        let mut scrypt_key = [0u8; 64];
        let (half1, half2) = {
            let salt = [&address_hash[..4], &entropy[..8]].concat();
            let params = scrypt::Params::new(10, 1, 1, 64)?;
            scrypt::scrypt(pass_point, &salt, &params, &mut scrypt_key)?;
            scrypt_key.split_at_mut(32)
        };

        let cipher = aes::Aes256::new_from_slice(half2)?;
        let (part1, part2) = half1.split_at_mut(16);

        part1[..16].xor(&seed[..16]);
        cipher.encrypt_block(GenericArray::from_mut_slice(part1));

        part2[..8].xor(&part1[8..16]);
        part2[8..16].xor(&seed[16..24]);
        cipher.encrypt_block(GenericArray::from_mut_slice(part2));

        let flag = if compressed { 0x20 } else { 0x00 } | if lot_seq { 0x40 } else { 0x00 };
        let result = [
            &PRE_EC[..2],
            &[flag][..1],
            &address_hash[..4],
            &entropy[..8],
            &part1[..8],
            &part2[..16],
        ]
        .concat();
        Ok(base58::encode_check(&result))
    }

    fn decrypt_ec_key(wif_ec_key: &str, passphrase: &str) -> Result<PrivateKey, Bip38Error> {
        let eprvk = base58::decode_check(wif_ec_key)?;
        if eprvk[..2] != PRE_EC {
            return Err(Bip38Error::InvalidKey);
        }
        let (compressed, lot_seq) = (eprvk[2] & 0x20 == 0x20, eprvk[2] & 0x04 == 0x04);
        let address_hash: [u8; 4] = eprvk[3..7].try_into().unwrap();
        let entropy: [u8; 8] = eprvk[7..15].try_into().unwrap();
        let encrypted_part1: [u8; 8] = eprvk[15..23].try_into().unwrap();
        let encrypted_part2: [u8; 16] = eprvk[23..39].try_into().unwrap();
        let salt = match lot_seq {
            true => &entropy[..4],
            false => &entropy[..8],
        };

        let pass_factor: [u8; 32] = {
            let mut pre_factor = [0u8; 32];
            {
                let pass = passphrase.nfc().collect::<String>();
                let params = scrypt::Params::new(14, 8, 8, 64)?;
                scrypt::scrypt(pass.as_bytes(), salt, &params, &mut pre_factor)?;
            }
            match lot_seq {
                true => [&pre_factor[..32], &entropy].concat().sha256_n(2),
                false => pre_factor,
            }
        };

        let mut seed = [0u8; 64];
        {
            let pass_point: [u8; 33] = {
                let secp_pub = secp256k1::PublicKey::from_secret_key(
                    &Secp256k1::default(),
                    &secp256k1::SecretKey::from_slice(&pass_factor)?,
                );
                secp_pub.serialize()
            };
            let salt = [&address_hash[..4], &entropy[..8]].concat();
            let params = scrypt::Params::new(10, 1, 1, 64)?;
            scrypt::scrypt(&pass_point, &salt, &params, &mut seed)?;
        }

        let factor: [u8; 32] = {
            let (half1, half2) = seed.split_at_mut(32);
            let (part1, part2) = half1.split_at_mut(16);
            let cipher = aes::Aes256::new(GenericArray::from_mut_slice(half2));

            let mut tmp2 = encrypted_part2;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut tmp2));
            part2[..16].xor(&tmp2[..16]);

            let mut tmp1 = [&encrypted_part1[..8], &part2[..8]].concat();
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut tmp1));
            part1[..16].xor(&tmp1[..16]);

            [&part1[..16], &part2[8..16]].concat().sha256_n(2)
        };

        // private key
        let prvk = {
            let prv = secp256k1::SecretKey::from_slice(&pass_factor)?
                .mul_tweak(&secp256k1::Scalar::from_be_bytes(factor)?)?;
            match compressed {
                true => PrivateKey::new(prv, Network::Bitcoin),
                false => PrivateKey::new_uncompressed(prv, Network::Bitcoin),
            }
        };
        // checksum
        if address_hash != prvk.p2pkh()?.as_bytes().sha256_n(2)[..4] {
            return Err(Bip38Error::InvalidPassphrase);
        }
        Ok(prvk)
    }
}

/// BIP38 trait for encrypting and decrypting private keys.
/// # Reference
///  [Definition](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
///  [Description](https://blockcoach.com/2023/202306/2023-06-20-A-BIP38/)
///  [Implementation](https://github.com/ceca69ec/bip38)
pub trait Bip38 {
    fn bip38_encrypt(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn bip38_decrypt(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn bip38_ec_factor(&self, lot: u32, seq: u32) -> Result<String, Bip38Error>;
    fn bip38_ec_generate(&self) -> Result<String, Bip38Error>;
}

impl Bip38 for str {
    fn bip38_encrypt(&self, passphrase: &str) -> Result<String, Bip38Error> {
        let prvk = PrivateKey::from_wif(self)?;
        prvk.encrypt_non_ec(passphrase)
    }

    fn bip38_decrypt(&self, passphrase: &str) -> Result<String, Bip38Error> {
        if self.starts_with("6P") && self.len() == 58 {
            let pre = base58::decode_check(self)?[..2].to_vec();
            if pre == PRE_NON_EC {
                let prvk = PrivateKey::decrypt_non_ec(self, passphrase)?;
                return Ok(prvk.to_wif());
            } else if pre == PRE_EC {
                let prvk = EcMultiply::decrypt_ec_key(self, passphrase)?;
                return Ok(prvk.to_wif());
            }
        }
        Err(Bip38Error::InvalidKey)
    }

    fn bip38_ec_factor(&self, lot: u32, seq: u32) -> Result<String, Bip38Error> {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        EcMultiply::generate_ec_pass(self, salt, lot, seq)
    }

    fn bip38_ec_generate(&self) -> Result<String, Bip38Error> {
        let mut seed = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut seed);
        EcMultiply::generate_ec_key(seed, self)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Bip38Error {
    #[error("Invalid BIP38 encrypted key")]
    InvalidKey,
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Invalid lot or sequence number: lot: {0}, seq: {1}")]
    InvalidEcNumber(u32, u32),
    #[error("Invalid ec passphrase")]
    InvalidEcFactor,
    #[error("Base58 error: {0}")]
    Base58Error(#[from] bitcoin::base58::Error),
    #[error("Invalid WIF: {0}")]
    InvalidWif(#[from] bitcoin::key::FromWifError),
    #[error("Inner error: {0}")]
    InnerError(String),
}

macro_rules! derive_error {
    ($e:expr, $source:ty) => {
        impl From<$source> for Bip38Error {
            fn from(e: $source) -> Self {
                $e(e.to_string())
            }
        }
    };
}
derive_error!(Bip38Error::InnerError, aes::cipher::InvalidLength);
derive_error!(Bip38Error::InnerError, scrypt::errors::InvalidOutputLen);
derive_error!(Bip38Error::InnerError, scrypt::errors::InvalidParams);
derive_error!(Bip38Error::InnerError, bitcoin::secp256k1::Error);
derive_error!(Bip38Error::InnerError, secp256k1::scalar::OutOfRangeError);

trait Sha256N {
    fn sha256_n(&self, n: usize) -> [u8; 32];
}

impl Sha256N for [u8] {
    #[inline(always)]
    fn sha256_n(&self, n: usize) -> [u8; 32] {
        assert!(n > 0, "Cannot hash zero times");

        use bitcoin::{hashes::Hash, hashes::sha256};
        let mut hash = sha256::Hash::hash(self).to_byte_array();
        for _ in 1..n {
            hash = sha256::Hash::hash(&hash).to_byte_array();
        }
        hash
    }
}

trait ByteOperation {
    fn xor(&mut self, other: &Self);
}

impl ByteOperation for [u8] {
    #[inline(always)]
    fn xor(&mut self, other: &Self) {
        debug_assert!(self.len() == other.len());
        (0..self.len()).for_each(|i| self[i] ^= other[i]);
    }
}

trait SecpOperation {
    fn p2pkh(&self) -> Result<String, Bip38Error>;
}

impl SecpOperation for PrivateKey {
    #[inline(always)]
    fn p2pkh(&self) -> Result<String, Bip38Error> {
        let pub_key = self.public_key(&Secp256k1::default());
        let address = Address::p2pkh(pub_key, NetworkKind::Main).to_string();
        Ok(address)
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

    #[test]
    fn test_ec_pass() -> Result<(), anyhow::Error> {
        const TEST_DATA: &[&str] = &[
            //EC multiply, no compression, no lot/sequence numbers
            "TestingOneTwoThree",
            "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
            "A50DBA6772CB9383",
            "0",
            "0",
            "Satoshi",
            "passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
            "67010A9573418906",
            "0",
            "0",
            // EC multiply, no compression, lot/sequence numbers
            "MOLON LABE",
            "passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
            "4FCA5A9700000000",
            "263183",
            "1",
            "ΜΟΛΩΝ ΛΑΒΕ",
            "passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
            "C40EA76F00000000",
            "806938",
            "1",
        ];

        use hex::FromHex;
        for data in TEST_DATA.chunks(5) {
            let (pass, factor, salt, lot, seq) = (
                data[0],
                data[1],
                Vec::from_hex(data[2])?.try_into().unwrap(),
                data[3].parse()?,
                data[4].parse()?,
            );

            let bs = base58::decode_check(factor)?;
            if lot > 0 || seq > 0 {
                assert_eq!(bs[..8], EcMultiply::PRE_EC_PASS_SEQ);
            } else {
                assert_eq!(bs[..8], EcMultiply::PRE_EC_PASS_NON);
            }
            println!("salt: {:x?}", &bs[8..16]);

            let ec_pass = EcMultiply::generate_ec_pass(pass, salt, lot, seq)?;
            assert_eq!(ec_pass, factor);
        }
        Ok(())
    }

    #[test]
    fn test_ec_decrypt() -> Result<(), anyhow::Error> {
        const TEST_DATA: &[&str] = &[
            // EC multiply, no compression, no lot/sequence numbers
            "TestingOneTwoThree",
            "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
            "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
            "Satoshi",
            "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
            "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH",
            // EC multiply, no compression, lot/sequence numbers
            "MOLON LABE",
            "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
            "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8",
            "ΜΟΛΩΝ ΛΑΒΕ",
            "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
            "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D",
        ];
        for data in TEST_DATA.chunks(6) {
            let (pass, wif, pk) = (data[0], data[1], data[2]);
            assert_eq!(wif.bip38_decrypt(pass)?, pk);
        }
        Ok(())
    }

    #[test]
    fn test_ec_generate() -> Result<(), anyhow::Error> {
        const TEST_DATA: &[&str] = &[
            // EC multiply, no compression, no lot/sequence numbers
            "69b14acff7bf5b659d43f73f9274631308ee405700fc8585",
            "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
            "6PnUPcXkiq1Ht3yaVTuCSBxEhAqJguPGyQQbCBz2Vg6LfiKdfTdmY9sPiL",
            "69b14acff7bf5b659d43f73f9274631308ee405700fc8585",
            "passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
            "6PnP4qjWDqJkeh6eHFkGyAPNofTTaYBsPDrEod8kG1soUu7jPpvoAVJPYr",
            // EC multiply, no compression, lot/sequence numbers
            "69b14acff7bf5b659d43f73f9274631308ee405700fc8585",
            "passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
            "6Q2Yf84ApjSoymHgpHyoaa1wgerDAvtp5XXoVc2KE65BQt5WPzMnjWDN9E",
            "69b14acff7bf5b659d43f73f9274631308ee405700fc8585",
            "passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
            "6Q2a23aHp9ggjNXHaBRnapfViMprg7aKBQVG2gc2D2m6ceeWiKAfnMtd25",
        ];
        for data in TEST_DATA.chunks(3) {
            let (seed, factor, wif) = (hex::decode(data[0])?.try_into().unwrap(), data[1], data[2]);
            let ec_key = EcMultiply::generate_ec_key(seed, factor)?;
            assert_eq!(ec_key, wif);
        }
        Ok(())
    }

    #[test]
    fn test_ec() -> Result<(), anyhow::Error> {
        const TEST_DATA: &[&str] = &[
            "TestingOneTwoThree",
            "Satoshi",
            "MOLON LABE",
            "ΜΟΛΩΝ ΛΑΒΕ",
            "バンドメイド",
        ];
        for passphrase in TEST_DATA {
            assert!(
                passphrase
                    .bip38_ec_factor(0, 0)?
                    .bip38_ec_generate()?
                    .bip38_decrypt(passphrase)
                    .is_ok()
            );
        }
        Ok(())
    }
}
