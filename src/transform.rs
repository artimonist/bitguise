use super::bip39::Mnemonic;
use super::encrypt::mnemonic::{ByteOperation, Derivation, MnemonicEx};
use crate::BIP38;
use anyhow::anyhow;
use bitcoin::{Network, PrivateKey, base58};

type Result<T = ()> = anyhow::Result<T>;

pub trait Transform {
    fn mnemonic_to_wif(&self, passphrase: &str) -> Result<String>;
    fn mnemonic_from_wif(&self, passphrase: &str) -> Result<String>;
}

impl Transform for str {
    fn mnemonic_to_wif(&self, passphrase: &str) -> Result<String> {
        let mnemonic: Mnemonic = self.parse()?;

        // let verify_word = (mnemonic.into() as MnemonicEx).verify_word().unwrap();
        let verify_word = {
            let address = MnemonicEx::derive_path_address(&mnemonic, "m/0'/0'")?;
            let addr_hash: u8 = address.as_bytes().sha256_n(2)[0];
            let size_flag: u8 = 8 - (mnemonic.size() as u8 / 3); // 4 | 3 | 2 | 1 | 0
            let verify_index: u16 = ((size_flag as u16) << 8) | (addr_hash as u16);
            let verify_word = mnemonic.language().word_at(verify_index as usize).unwrap();
            verify_word
        };

        let mut entropy = mnemonic.entropy();
        entropy.resize_with(32, || rand::random::<u8>());

        let wif = PrivateKey::from_slice(&entropy, Network::Bitcoin)?.to_wif();
        Ok(format!("{wif}; {verify_word}"))
    }

    /// Extract mnemonic from WIF
    /// # Examples:
    ///   "6P..."
    ///   "K...", "L...", "5..."
    ///   "K...; W", "L...; W", "5...; W" // W: verify word
    ///   "K...; C", "L...; C", "5...; C" // C: desired size
    fn mnemonic_from_wif(&self, passphrase: &str) -> Result<String> {
        let (wif, verify) = self.extract_verify();
        let wif_original = match (wif.as_bytes()[0] as char, wif.len()) {
            ('6', 58) if wif.starts_with("6P") => wif.bip38_decrypt(passphrase)?, // bip38 encrypted
            ('K', 52) | ('L', 52) | ('5', 51) => wif.to_string(),                 // private key
            _ => return Err(anyhow!("Invalid WIF format")),
        };
        let entropy = &base58::decode(&wif_original)?[1..33];

        println!("entropy: {entropy:x?}");
        Ok(String::new())
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
        let wif_ex = "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX; 胞";
        let wif_en = "";

        println!("{}", wif_ex.contains([';', ' ']));
        let (wif, verify) = wif_ex.rsplit_once([';', ' ']).unwrap_or((wif_ex, ""));
        println!(
            "[{wif}] -- [{verify}] -- [{}]",
            verify.trim_matches([';', ' '])
        );

        assert_eq!(mnemonic.mnemonic_to_wif("")?, wif_ex);
        assert_eq!(mnemonic.mnemonic_to_wif("123456")?, wif_en);

        Ok(())
    }
}
