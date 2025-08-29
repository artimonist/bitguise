use super::bip39::Mnemonic;
use super::encrypt::Error;
use super::encrypt::mnemonic::{ByteOperation, MnemonicExtension};
use super::encrypt::verify::Verify;
use anyhow::anyhow;
use bitcoin::base58;

type Result<T = ()> = anyhow::Result<T>;

/// Transform mnemonic to wif or retrieve mnemonic from wif.
pub trait Transform {
    /// Transform mnemonic to wif
    /// If passphrase is empty, return private key wif and verify word.  
    /// If passphrase not empty, return bip38 encrypted wif and verify word.  
    fn mnemonic_to_wif(&self) -> Result<String>;

    /// Retrieve mnemonic from WIF
    /// For private key wif, passphrase will be ignore.  
    /// For bip38 encrypted wif, passphrase is required.
    /// If verify word is given, it will be used to verify the mnemonic is correct or not.  
    /// If verify word is not given, return 24 words mnemonic or user given size.
    fn mnemonic_from_wif(&self) -> Result<String>;
}

impl Transform for str {
    fn mnemonic_to_wif(&self) -> Result<String> {
        let mnemonic: Mnemonic = self.parse()?;
        let mut entropy = mnemonic.entropy();
        {
            let random = mnemonic.default_address()?.as_bytes().sha256_n(1);
            entropy.extend_from_slice(&random[..32 - entropy.len()]);
        }

        let wif = {
            // compressed private key wif format
            let wif_bytes = [&[0x80], entropy.as_slice(), &[0x01]].concat();
            base58::encode_check(&wif_bytes)
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
    fn mnemonic_from_wif(&self) -> Result<String> {
        let (wif, verify) = Verify::split(self)?;

        let entropy = {
            let wif_original = match (wif.as_bytes()[0] as char, wif.len()) {
                ('K', 52) | ('L', 52) => wif.to_string(), // compressed private key
                _ => return Err(anyhow!("Invalid WIF format")),
            };
            &base58::decode(&wif_original)?[1..33]
        };

        let len = verify.desired_bytes();
        let mnemonic = Mnemonic::new(&entropy[..len], verify.language())?;
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

        assert_eq!(mnemonic.mnemonic_to_wif()?, wif);
        assert_eq!(wif.mnemonic_from_wif()?, mnemonic);

        Ok(())
    }
}
