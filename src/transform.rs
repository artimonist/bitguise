use super::bip39::Mnemonic;
use super::encrypt::mnemonic::{ByteOperation, Derivation, MnemonicEx};
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
        {
            let address = MnemonicEx::derive_path_address(&mnemonic, "m/0'/0'")?;
            let random = address.as_bytes().sha256_n(1);
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
        let (wif, verify) = Verify::parse(self)?;

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
        if let Some(check_sum) = verify.verify_sum() {
            let address = MnemonicEx::derive_path_address(&mnemonic, MnemonicEx::DERIVE_PATH)?;
            if check_sum != address.as_bytes().sha256_n(2)[0] {
                return Err(anyhow!("Verify word does not match mnemonic"));
            }
        }
        Ok(mnemonic.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    Word(Language, usize), // Mnemonic size (3 bits) and derivation address (m/0'/0') hash (8 bits).
    Size(u8),              // Mnemonic encrypt or decrypt desired size.
}

impl Verify {
    pub const DELIMITER: char = ';';

    pub fn desired_size(&self) -> usize {
        match self {
            Verify::Word(_, i) => (8 - (*i >> 8)) * 3,
            Verify::Size(n) => *n as usize,
        }
    }

    #[inline(always)]
    pub fn desired_bytes(&self) -> usize {
        self.desired_size() / 3 * 4
    }

    #[inline]
    pub fn language(&self) -> Language {
        match self {
            Verify::Word(lang, _) => *lang,
            Verify::Size(_) => Language::default(),
        }
    }

    pub fn verify_sum(&self) -> Option<u8> {
        match self {
            Verify::Word(_, i) => Some((i & 0xff) as u8),
            Verify::Size(_) => None,
        }
    }

    pub fn verify_word(&self) -> Option<&'static str> {
        match self {
            Verify::Word(lang, i) => lang.word_at(*i),
            Verify::Size(_) => None,
        }
    }

    pub fn parse(s: &str) -> Result<(&str, Verify)> {
        let (s1, s2) = s.rsplit_once(Self::DELIMITER).unwrap_or((s, ""));

        if s2.is_empty() {
            let count = s1.split_whitespace().count();
            if Mnemonic::valid_size(count) {
                Ok((s1, Verify::Size(count as u8))) // mnemonic size
            } else {
                Ok((s1, Verify::Size(24))) // default size
            }
        } else {
            Ok((s1.trim_end(), s2.trim_start().parse()?)) // size or word
        }
    }
}

impl std::str::FromStr for Verify {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(n) = s.parse::<u8>()
            && matches!(n, 12 | 15 | 18 | 21 | 24)
        {
            Ok(Verify::Size(n))
        } else if let Some(&lang) = Language::detect(s).first()
            && let Some(index) = lang.index_of(s)
            && (index >> 8) < 5
        {
            Ok(Verify::Word(lang, index))
        } else {
            Err(anyhow!("Invalid verify word"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_parse() -> Result {
        const TEST_WIF: &[&str] = &[
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX",
            "胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX;胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX; 胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX ;胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX ; 胞",
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX  ;  胞",
        ];
        const TEST_MNEMONIC: &[&str] = &[
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔;胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔; 胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔 ;胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔 ; 胞",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔  ;  胞",
        ];
        for data in [TEST_WIF, TEST_MNEMONIC] {
            for content in data[2..].iter() {
                let (s, v) = Verify::parse(content)?;
                assert_eq!(s, data[0]);
                assert_eq!(v.verify_word().unwrap(), data[1]);
            }
        }
        const TEST_NONE: &[&str] = &[
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因",
        ];
        for data in TEST_NONE {
            let (s, v) = Verify::parse(data)?;
            assert_eq!(s, *data);
            let n = s.split_whitespace().count();
            if Mnemonic::valid_size(n) {
                assert_eq!(v, Verify::Size(n as u8));
            } else {
                assert_eq!(v, Verify::Size(24));
            }
        }
        Ok(())
    }

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
