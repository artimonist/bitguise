use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Address, Network, NetworkKind, PrivateKey, PublicKey, base58};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

pub trait NoneEc {
    fn encrypt_non_ec(wif: &str, passphrase: &str) -> Result<String, Bip38Error> {
        let prvk = PrivateKey::from_wif(wif)?;
        let compress = prvk.compressed;
        let salt = prvk.p2pkh()?.as_bytes().sha256_n(2)[0..4].to_vec();

        let mut scrypt_key = [0u8; 64];
        {
            let pass = passphrase.nfc().collect::<String>();
            let params = scrypt::Params::new(14, 8, 8, 64)?;
            scrypt::scrypt(pass.as_bytes(), &salt, &params, &mut scrypt_key)?;
        }

        let (part1, part2) = {
            let (half1, half2) = scrypt_key.split_at_mut(32);
            let cipher = aes::Aes256::new_from_slice(half2)?;

            half1[..32].xor(&prvk.to_bytes()[..32]);
            let (part1, part2) = half1.split_at_mut(16);
            cipher.encrypt_block(GenericArray::from_mut_slice(part1));
            cipher.encrypt_block(GenericArray::from_mut_slice(part2));

            (part1, part2)
        };

        let compress: [u8; 1] = if compress { [0xe0] } else { [0xc0] };
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

    fn decrypt_non_ec(wif: &str, passphrase: &str) -> Result<String, Bip38Error> {
        let mut ebuffer = base58::decode_check(wif)?;
        if ebuffer.len() != 39 || ebuffer[..2] != PRE_NON_EC {
            return Err(Bip38Error::InvalidKey);
        }
        let [ref flag, ref salt, epart1, epart2] = ebuffer[2..].segments_mut([1, 4, 16, 16]);
        let compress = flag[0] & 0x20 == 0x20;

        let mut scrypt_key = [0u8; 64];
        {
            let pass = passphrase.nfc().collect::<String>();
            let params = scrypt::Params::new(14, 8, 8, 64)?;
            scrypt::scrypt(pass.as_bytes(), salt, &params, &mut scrypt_key)?;
        };

        // Decrypt the two parts of the key
        let (half1, half2) = scrypt_key.split_at_mut(32);
        {
            let cipher = aes::Aes256::new_from_slice(half2)?;
            cipher.decrypt_block(GenericArray::from_mut_slice(epart1));
            cipher.decrypt_block(GenericArray::from_mut_slice(epart2));
            half1[..16].xor(epart1);
            half1[16..32].xor(epart2);
        }

        // create private key
        let mut prvk = PrivateKey::from_slice(half1, NetworkKind::Main)?;
        prvk.compressed = compress;

        // Verify the checksum
        if *salt != &prvk.p2pkh()?.as_bytes().sha256_n(2)[..4] {
            return Err(Bip38Error::InvalidPassphrase);
        }
        Ok(prvk.to_string())
    }
}

pub trait EcMultiply {
    /// EC_PASS has "lot" and "sequence".
    const PRE_EC_PASS_SEQ: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];

    /// EC_PASS not has "lot" and "sequence".
    const PRE_EC_PASS_NON: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53];

    fn generate_ec_factor(
        passphrase: &str,
        salt: [u8; 8],
        lot: u32,
        seq: u32,
    ) -> Result<String, Bip38Error> {
        match (lot, seq) {
            (100000..=999999, 1..=4095) => {
                let salt = salt[..4].to_vec();
                let entropy = [&salt[..4], &(lot << 12 | seq).to_be_bytes()[..4]].concat();

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

    fn generate_ec_key(seed: [u8; 24], ec_factor: &str) -> Result<String, Bip38Error> {
        let compress = true;
        let ec_pass = base58::decode_check(ec_factor)?;
        let [ec_pre, entropy, pass_point] = ec_pass.segments([8, 8, 33]);
        let lot_seq = match ec_pre {
            v if v == Self::PRE_EC_PASS_SEQ => true,
            v if v == Self::PRE_EC_PASS_NON => false,
            _ => return Err(Bip38Error::InvalidEcFactor),
        };

        let address_hash = {
            let factor = seed.sha256_n(2);
            let mut pub_key = PublicKey::from_slice(pass_point)?.mul_tweak(factor)?;
            pub_key.compressed = true;
            pub_key.p2pkh()?.as_bytes().sha256_n(2)[0..4].to_vec()
        };

        let mut scrypt_key = [0u8; 64];
        {
            let salt = [&address_hash[..4], &entropy[..8]].concat();
            let params = scrypt::Params::new(10, 1, 1, 64)?;
            scrypt::scrypt(pass_point, &salt, &params, &mut scrypt_key)?;
        };

        let (ref part1, ref part2) = {
            let [part1, part2, aes_key] = scrypt_key.segments_mut([16, 16, 32]);

            let cipher = aes::Aes256::new_from_slice(aes_key)?;

            part1[..16].xor(&seed[..16]);
            cipher.encrypt_block(GenericArray::from_mut_slice(part1));

            part2[..8].xor(&part1[8..16]);
            part2[8..16].xor(&seed[16..24]);
            cipher.encrypt_block(GenericArray::from_mut_slice(part2));

            (part1, part2)
        };

        let flag = if compress { 0x20 } else { 0x00 } | if lot_seq { 0x40 } else { 0x00 };
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

    fn decrypt_ec_key(wif_ec_key: &str, passphrase: &str) -> Result<String, Bip38Error> {
        let ebuffer = base58::decode_check(wif_ec_key)?;
        if ebuffer.len() != 39 || ebuffer[..2] != PRE_EC {
            return Err(Bip38Error::InvalidKey);
        }
        let [flag, address_hash, entropy, epart1, epart2] = ebuffer[2..].segments([1, 4, 8, 8, 16]);
        let (compress, lot_seq) = (flag[0] & 0x20 == 0x20, flag[0] & 0x04 == 0x04);
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
                true => [&pre_factor[..32], &entropy[..8]].concat().sha256_n(2),
                false => pre_factor,
            }
        };

        let mut seed = [0u8; 64];
        {
            let pass_point = PrivateKey::from_slice(&pass_factor, Network::Bitcoin)?
                .public_key(&Secp256k1::default())
                .to_bytes();
            let salt = [&address_hash[..4], &entropy[..8]].concat();
            let params = scrypt::Params::new(10, 1, 1, 64)?;
            scrypt::scrypt(&pass_point, &salt, &params, &mut seed)?;
        }

        let factor: [u8; 32] = {
            let [part1, part2, aes_key] = seed.segments_mut([16, 16, 32]);
            let cipher = aes::Aes256::new(GenericArray::from_mut_slice(aes_key));

            let tmp2 = &mut epart2.to_vec();
            cipher.decrypt_block(GenericArray::from_mut_slice(tmp2));
            part2[..16].xor(&tmp2[..16]);

            let tmp1 = &mut [&epart1[..8], &part2[..8]].concat();
            cipher.decrypt_block(GenericArray::from_mut_slice(tmp1));
            part1[..16].xor(&tmp1[..16]);

            [&part1[..16], &part2[8..16]].concat().sha256_n(2)
        };

        // private key
        let mut prvk = PrivateKey::from_slice(&pass_factor, Network::Bitcoin)?.mul_tweak(factor)?;
        prvk.compressed = compress;

        // checksum
        if address_hash != &prvk.p2pkh()?.as_bytes().sha256_n(2)[..4] {
            return Err(Bip38Error::InvalidPassphrase);
        }
        Ok(prvk.to_string())
    }
}

/// BIP38 trait for encrypting and decrypting private keys.
/// # Reference
///  [Definition](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
///  [Description](https://blockcoach.com/2023/202306/2023-06-20-A-BIP38/)
///  [Implementation](https://github.com/ceca69ec/bip38)
pub trait Bip38: NoneEc + EcMultiply {
    fn bip38_encrypt(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn bip38_decrypt(&self, passphrase: &str) -> Result<String, Bip38Error>;
    fn bip38_ec_factor(&self, lot: u32, seq: u32) -> Result<String, Bip38Error>;
    fn bip38_ec_generate(&self) -> Result<String, Bip38Error>;
}

impl NoneEc for str {}
impl EcMultiply for str {}
impl Bip38 for str {
    #[inline(always)]
    fn bip38_encrypt(&self, passphrase: &str) -> Result<String, Bip38Error> {
        Self::encrypt_non_ec(self, passphrase)
    }

    #[inline(always)]
    fn bip38_decrypt(&self, passphrase: &str) -> Result<String, Bip38Error> {
        if self.starts_with("6P") && self.len() == 58 {
            let pre = base58::decode_check(self)?[..2].to_vec();
            if pre == PRE_NON_EC {
                return Self::decrypt_non_ec(self, passphrase);
            } else if pre == PRE_EC {
                return Self::decrypt_ec_key(self, passphrase);
            }
        }
        Err(Bip38Error::InvalidKey)
    }

    #[inline]
    fn bip38_ec_factor(&self, lot: u32, seq: u32) -> Result<String, Bip38Error> {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::generate_ec_factor(self, salt, lot, seq)
    }

    #[inline]
    fn bip38_ec_generate(&self) -> Result<String, Bip38Error> {
        let mut seed = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::generate_ec_key(seed, self)
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
derive_error!(Bip38Error::InnerError, secp256k1::scalar::OutOfRangeError);
derive_error!(Bip38Error::InnerError, bitcoin::secp256k1::Error);
derive_error!(Bip38Error::InnerError, bitcoin::key::FromSliceError);

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

trait SecpOperation
where
    Self: Sized,
{
    fn p2pkh(&self) -> Result<String, Bip38Error>;
    fn mul_tweak(self, scalar: [u8; 32]) -> Result<Self, Bip38Error>;
}

impl SecpOperation for PrivateKey {
    #[inline(always)]
    fn p2pkh(&self) -> Result<String, Bip38Error> {
        let pub_key = self.public_key(&Secp256k1::default());
        let address = Address::p2pkh(pub_key, NetworkKind::Main).to_string();
        Ok(address)
    }

    #[inline(always)]
    fn mul_tweak(mut self, scalar: [u8; 32]) -> Result<Self, Bip38Error> {
        use bitcoin::secp256k1::Scalar;
        self.inner = self.inner.mul_tweak(&Scalar::from_be_bytes(scalar)?)?;
        Ok(self)
    }
}

impl SecpOperation for PublicKey {
    #[inline(always)]
    fn p2pkh(&self) -> Result<String, Bip38Error> {
        let address = Address::p2pkh(self, NetworkKind::Main).to_string();
        Ok(address)
    }

    #[inline(always)]
    fn mul_tweak(mut self, scalar: [u8; 32]) -> Result<Self, Bip38Error> {
        use bitcoin::secp256k1::Scalar;
        let scalar = Scalar::from_be_bytes(scalar)?;
        self.inner = self.inner.mul_tweak(&Secp256k1::default(), &scalar)?;
        Ok(self)
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

            let encrypted = str::encrypt_non_ec(wif, pwd).expect("Encryption failed");
            assert_eq!(encrypted, *enc_wif, "Encryption mismatch");

            let decrypted = str::decrypt_non_ec(&encrypted, pwd).expect("Decryption failed");
            assert_eq!(decrypted, *wif, "Decryption mismatch");
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
                assert_eq!(bs[..8], str::PRE_EC_PASS_SEQ);
            } else {
                assert_eq!(bs[..8], str::PRE_EC_PASS_NON);
            }
            println!("salt: {:x?}", &bs[8..16]);

            let ec_pass = str::generate_ec_factor(pass, salt, lot, seq)?;
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
            let ec_key = str::generate_ec_key(seed, factor)?;
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
