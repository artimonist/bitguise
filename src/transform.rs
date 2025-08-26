use super::bip39::Mnemonic;
use super::encrypt::mnemonic::MnemonicEx;
use crate::{BIP38, Language};
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
        entropy.resize_with(32, || rand::random::<u8>());

        let wif_bytes = [&[0x80], entropy.as_slice(), &[0x01]].concat();
        let mut wif = base58::encode_check(&wif_bytes);
        if !passphrase.is_empty() {
            wif = wif.bip38_encrypt(passphrase)?;
        };

        if let Some(verify) = MnemonicEx::from(mnemonic).verify_word() {
            Ok(format!("{wif}; {verify}"))
        } else {
            Ok(wif)
        }
    }

    /// Extract mnemonic from WIF
    /// # Examples:
    ///   "6P..."
    ///   "K...", "L...", "5..."
    ///   "K...; W", "L...; W", "5...; W" // W: verify word
    ///   "K...; N", "L...; N", "5...; N" // N: desired size
    fn mnemonic_from_wif(&self, passphrase: &str) -> Result<String> {
        let (wif, verify) = self.extract_verify();
        let wif_original = match (wif.as_bytes()[0] as char, wif.len()) {
            ('6', 58) if wif.starts_with("6P") => wif.bip38_decrypt(passphrase)?, // bip38 encrypted
            ('K', 52) | ('L', 52) | ('5', 51) => wif.to_string(),                 // private key
            _ => return Err(anyhow!("Invalid WIF format")),
        };
        let entropy = &base58::decode(&wif_original)?[1..33];

        // no verify word, return 24 words mnemonic directly
        if verify.is_empty() {
            let mnemonic = Mnemonic::from_entropy(entropy, Default::default())?;
            return Ok(mnemonic.to_string());
        }

        // only desired size given, return mnemonic with the size
        if let Ok(size) = self.parse::<usize>()
            && matches!(size, 12 | 15 | 18 | 21 | 24)
        {
            let len = size / 3 * 4;
            let mnemonic = Mnemonic::from_entropy(&entropy[..len], Default::default())?;
            return Ok(mnemonic.to_string());
        }

        // verify word given, try to find the correct language and size
        let langs = Language::detect(verify)
            .into_iter()
            .filter(|&lang| match lang.index_of(verify) {
                Some(index) => (index >> 8) < 5, // size flag in 0..4
                None => false,
            })
            .collect::<Vec<Language>>();

        if langs.len() == 0 {
            return Err(anyhow!(
                "Cannot determine language from verify word: {langs:?}"
            ));
        }

        let lang = langs[0];
        let index = lang.index_of(verify).unwrap();
        let size = (8 - (index >> 8)) * 3; // desired size
        let check_sum = (index & 0xff) as u8; // check sum
        let len = size / 3 * 4;
        let mnemonic = Mnemonic::from_entropy(&entropy[..len], lang)?;
        if MnemonicEx::from(mnemonic.clone()).verify_sum() != Some(check_sum) {
            return Err(anyhow!("Verify word does not match mnemonic"));
        }
        Ok(mnemonic.to_string())
    }
}

trait MnemonicExtension {
    fn size_flag(&self) -> u8;
}

impl MnemonicExtension for Mnemonic {
    fn size_flag(&self) -> u8 {
        8 - (self.size() as u8 / 3) // 4 | 3 | 2 | 1 | 0
    }
}

trait VerifyExtension {
    const DELIMITER: &[char] = &[';', ' '];
    fn extract_verify(&self) -> (&str, &str);
}

impl VerifyExtension for str {
    fn extract_verify(&self) -> (&str, &str) {
        let delimiter = Self::DELIMITER;
        let (content, verify) = self.rsplit_once(delimiter).unwrap_or((self, ""));
        if matches!(content.split_whitespace().count(), 11 | 14 | 17 | 20 | 23) {
            return (self, ""); // only mnemonic, no verify word
        } else {
            (
                content.trim_end_matches(delimiter),
                verify.trim_start_matches(delimiter),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_verify() {
        const TEST_WIF: &[&str] = &[
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX",
            "胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX;胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX; 胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX ;胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX ; 胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX  ;  胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX 胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX    胞",
        ];
        const TEST_MNEMONIC: &[&str] = &[
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔;胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔; 胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔 ;胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔 ; 胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔  ;  胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔 胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔  胞",
        ];
        for data in [TEST_WIF, TEST_MNEMONIC] {
            for content in data[2..].iter() {
                let (a, b) = content.extract_verify();
                assert_eq!(a, data[0]);
                assert_eq!(b, data[1]);
            }
        }
        const TEST_NONE: &[&str] = &[
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因",
        ];
        for data in TEST_NONE {
            let (a, b) = data.extract_verify();
            assert_eq!(a, *data);
            assert_eq!(b, "");
        }
    }

    #[test]
    fn test_transform() -> Result {
        let mnemonic = "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔";
        // let wif_ex = "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX; 胞";
        // let wif_en = "6PYUcbHHu6y9CjAUBtqVVrDinGeUQhLeEQBKw4rjkki7KDrm33vwWugPBa; 胞";

        let wif = mnemonic.mnemonic_to_wif("")?;
        println!("WIF: {wif}");
        assert_eq!(wif.mnemonic_from_wif("")?, mnemonic, "{wif}");

        let wif = mnemonic.mnemonic_to_wif("123456")?;
        println!("WIF: {wif}");
        assert_eq!(wif.mnemonic_from_wif("123456")?, mnemonic, "{wif}");

        Ok(())
    }
}
