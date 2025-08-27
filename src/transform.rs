use super::bip39::Mnemonic;
use super::encrypt::mnemonic::{ByteOperation, Error, MnemonicExtension};
use super::encrypt::verify::Verify;
use crate::BIP38;
use anyhow::anyhow;
use bitcoin::base58;

type Result<T = ()> = anyhow::Result<T>;

/// Transform mnemonic to wif or retrieve mnemonic from wif.
/// # Compact mode:  
///   Wif contains mnemonic size flag in it self.  
///   If verify word lost or not given, wif can decrypt to mnemonic correctly.  
///   If verify word given, it can be used to verify the mnemonic is correct or not.  
///   For compressed private key: byte 33 (original value 0x01) left 3 bits will be mnemonic size flag.  
///   For bip38 encrypted private key: byte 2 (original value 0xe0) right 3 bits will be mnemonic size flag.  
///   So, compact mode wif can be `recognized`.  
/// # Non compact mode:  
///   Wif does not contain mnemonic size flag.  
///   If verify word lost or not given, wif can only decrypt to 24 words mnemonic or user given size.  
///   If verify word given, it can be used to verify the mnemonic is correct or not.  
///   For compressed private key: byte 33 (original value 0x01) will be 0x01.  
///   For bip38 encrypted private key: byte 2 (original value 0xe0) will be 0xe0.  
///   So, non compact mode wif can not be `recognized`.  
pub trait Transform {
    /// Transform mnemonic to wif
    /// If passphrase is empty, return private key wif and verify word.  
    /// If passphrase not empty, return bip38 encrypted wif and verify word.  
    fn mnemonic_to_wif(&self, passphrase: &str) -> Result<String>;

    /// Retrieve mnemonic from WIF
    /// For private key wif, passphrase will be ignore.  
    /// For bip38 encrypted wif, passphrase is required.
    /// If verify word is given, it will be used to verify the mnemonic is correct or not.  
    /// If verify word is not given, return 24 words mnemonic or user given size.
    fn mnemonic_from_wif(&self, passphrase: &str) -> Result<String>;
}

impl Transform for str {
    fn mnemonic_to_wif(&self, passphrase: &str) -> Result<String> {
        let mnemonic: Mnemonic = self.parse()?;
        let mut entropy = mnemonic.entropy();
        {
            let random = mnemonic.default_address()?.as_bytes().sha256_n(1);
            entropy.extend_from_slice(&random[..32 - entropy.len()]);
        }

        let wif = {
            let wif_bytes = [&[0x80], entropy.as_slice(), &[0x01]].concat();
            let mut wif = base58::encode_check(&wif_bytes);
            if !passphrase.is_empty() {
                wif = wif.bip38_encrypt(passphrase)?;
            };
            wif
        };

        let verify = Verify::from_mnemonic(&mnemonic)?;
        Ok(format!("{wif}; {verify}"))
    }

    /// Extract mnemonic from WIF
    /// # Examples:
    ///   "6P..."
    ///   "K...", "L...", "5..."
    ///   "K...; W", "L...; W", "5...; W" // W: verify word
    ///   "K...; N", "L...; N", "5...; N" // N: desired size
    fn mnemonic_from_wif(&self, passphrase: &str) -> Result<String> {
        let (wif, verify) = Verify::split(self)?;

        let entropy = {
            let wif_original = match (wif.as_bytes()[0] as char, wif.len()) {
                ('6', 58) if wif.starts_with("6P") => wif.bip38_decrypt(passphrase)?, // bip38 encrypted
                ('K', 52) | ('L', 52) | ('5', 51) => wif.to_string(),                 // private key
                _ => return Err(anyhow!("Invalid WIF format")),
            };
            &base58::decode(&wif_original)?[1..33]
        };

        let len = verify.desired_bytes();
        let mnemonic = Mnemonic::from_entropy(&entropy[..len], verify.language())?;
        if !verify.check_mnemonic(&mnemonic)? {
            return Err(Error::InvalidPass.into());
        }
        Ok(format!("{mnemonic}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform() -> Result {
        let mnemonic = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        let wif = "KyBAktKfYhgtcA63sRL2c5mc3quy3MXBUt8BfFeVc8E5eUkazoMS; 胞";
        let encrypted = "6PYToQVvVqL7yn7wxd1rTZSPJuePvA8SQoSkRYAvMwDnAqgEwkH4XdbURv; 胞";

        assert_eq!(mnemonic.mnemonic_to_wif("")?, wif);
        assert_eq!(wif.mnemonic_from_wif("")?, mnemonic);

        assert_eq!(mnemonic.mnemonic_to_wif("123456")?, encrypted);
        assert_eq!(encrypted.mnemonic_from_wif("123456")?, mnemonic,);

        Ok(())
    }
}
