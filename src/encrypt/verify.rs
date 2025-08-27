use super::mnemonic::MnemonicExtension;
use super::mnemonic::{ByteOperation, Error};
use crate::bip39::{Language, Mnemonic};

type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    Word(Language, usize), // Mnemonic size (3 bits) and derivation address (m/0'/0') hash (8 bits).
    Size(u8),              // Mnemonic encrypt or decrypt desired size.
}

impl Verify {
    pub const DELIMITER: char = ';';

    /// Create a `Verify` from a given `Mnemonic`.
    /// The `Verify` will contain the language and an index that encodes both the size
    /// of the mnemonic and a checksum derived from the default address.
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Verify> {
        let checksum: u8 = mnemonic.default_address()?.as_bytes().sha256_n(2)[0];
        let size_flag: usize = 8 - (mnemonic.size() / 3); // 4 | 3 | 2 | 1 | 0
        assert!(size_flag < 5);
        let index = (size_flag << 8) | (checksum as usize);
        Ok(Verify::Word(mnemonic.language(), index))
    }

    /// Check if the given `Mnemonic` matches the criteria defined in `Verify`.
    /// This includes verifying the size and, if applicable, the checksum.
    pub fn check_mnemonic(&self, mnemonic: &Mnemonic) -> Result<bool> {
        let checksum = mnemonic.default_address()?.as_bytes().sha256_n(2)[0];
        if self.desired_size() != mnemonic.size() {
            return Ok(false);
        }
        match self.verify_sum() {
            Some(v) => Ok(v == checksum),
            None => Ok(true),
        }
    }

    #[inline]
    pub fn desired_size(&self) -> usize {
        match *self {
            Verify::Word(_, i) => (8 - (i >> 8)) * 3,
            Verify::Size(n) => n as usize,
        }
    }

    #[inline(always)]
    pub fn desired_bytes(&self) -> usize {
        self.desired_size() / 3 * 4
    }

    #[inline]
    pub fn language(&self) -> Language {
        match *self {
            Verify::Word(lang, _) => lang,
            Verify::Size(_) => Language::default(),
        }
    }

    #[inline]
    pub fn verify_sum(&self) -> Option<u8> {
        match *self {
            Verify::Word(_, i) => Some((i & 0xff) as u8),
            Verify::Size(_) => None,
        }
    }

    // pub fn verify_word(&self) -> Option<&'static str> {
    //     match self {
    //         Verify::Word(lang, i) => lang.word_at(*i),
    //         Verify::Size(_) => None,
    //     }
    // }

    #[inline]
    pub fn split(s: &str) -> Result<(&str, Verify)> {
        let (content, _) = s
            .rsplit_once(Self::DELIMITER)
            .map_or((s, ""), |(s1, s2)| (s1.trim_end(), s2.trim_start()));
        Ok((content, s.parse()?))
    }

    #[inline]
    pub fn parse(s: &str) -> Result<(Mnemonic, Verify)> {
        let (content, _) = s
            .rsplit_once(Self::DELIMITER)
            .map_or((s, ""), |(s1, s2)| (s1.trim_end(), s2.trim_start()));
        Ok((content.parse()?, s.parse()?))
    }
}

impl Default for Verify {
    fn default() -> Self {
        Verify::Size(24)
    }
}
impl std::str::FromStr for Verify {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (content, word) = s
            .rsplit_once(Self::DELIMITER)
            .map_or((s, ""), |(s1, s2)| (s1.trim_end(), s2.trim_start()));

        if let Ok(n) = word.parse::<usize>()
            && Mnemonic::valid_size(n)
        {
            return Ok(Verify::Size(n as u8)); // desired size
        }

        if let Ok(mnemonic) = content.parse::<Mnemonic>() {
            let lang = mnemonic.language();

            // if the mnemonic is valid, only accept verify word from the same language
            // and default verify size is the mnemonic size
            if word.is_empty() {
                Ok(Verify::Size(mnemonic.size() as u8)) // no verify
            } else if let Some(i) = lang.index_of(word)
                && (i >> 8) < 5
            {
                Ok(Verify::Word(lang, i)) // verify word
            } else {
                Err(Error::InvalidVerify)
            }
        } else if word.is_empty() {
            Ok(Verify::default()) // no verify
        } else if let Some(&lang) = Language::detect(word).first()
            && let Some(i) = lang.index_of(word)
            && (i >> 8) < 5
        {
            Ok(Verify::Word(lang, i)) // verify word
        } else {
            Err(Error::InvalidVerify)
        }
    }
}

impl std::fmt::Display for Verify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Verify::Word(lang, i) => write!(f, "{}", lang.word_at(i).unwrap_or_default()),
            Verify::Size(n) => write!(f, "{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_split() -> Result {
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
                let (s, v) = Verify::split(content)?;
                assert_eq!(s, data[0]);
                assert_eq!(format!("{v}"), data[1]);
            }
        }
        const TEST_NONE: &[&str] = &[
            "KyBAktKfYhgtcA63sRL2c5mc3quy3yepyExduUHzzFSSaHkpDFNX",
            "派 贤 博 如 恐 臂 诺 职 畜 给 压 钱 牲 案 隔",
            "生 别 斑 票 纤 费 普 描 比 销 柯 委 敲 普 伍 慰 思 人 曲 燥 恢 校 由 因",
        ];
        for data in TEST_NONE {
            let (s, v) = Verify::split(data)?;
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
    fn test_verify_parse() -> Result {
        const TEST_WIF: &[&str] = &["坏 火 发 恐 晒 为 陕 伪 镜 锻 略 越 力 秦 音"];
        for data in TEST_WIF {
            let (mnemonic, verify) = Verify::parse(data)?;
            println!("{mnemonic}, {verify}");
        }
        Ok(())
    }
}
