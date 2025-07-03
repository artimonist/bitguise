use std::str::FromStr;

const CHINESE_SIMPLIFIED: &str = include_str!("raw/chinese_simplified.txt");
const CHINESE_TRADITIONAL: &str = include_str!("raw/chinese_traditional.txt");
const CZECH: &str = include_str!("raw/czech.txt");
const ENGLISH: &str = include_str!("raw/english.txt");
const FRENCH: &str = include_str!("raw/french.txt");
const ITALIAN: &str = include_str!("raw/italian.txt");
const JAPANESE: &str = include_str!("raw/japanese.txt");
const KOREAN: &str = include_str!("raw/korean.txt");
const PORTUGUESE: &str = include_str!("raw/portuguese.txt");
const SPANISH: &str = include_str!("raw/spanish.txt");

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Language {
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    #[default]
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Portuguese,
    Spanish,
}

impl Language {
    pub fn all() -> [Language; 10] {
        [
            Self::ChineseSimplified,
            Self::ChineseTraditional,
            Self::Czech,
            Self::English,
            Self::French,
            Self::Italian,
            Self::Japanese,
            Self::Korean,
            Self::Portuguese,
            Self::Spanish,
        ]
    }

    pub fn from_str(lang: &str) -> Option<Self> {
        match lang.to_lowercase().as_str() {
            "chinese_simplified" => Some(Self::ChineseSimplified),
            "chinese_traditional" => Some(Self::ChineseTraditional),
            "czech" => Some(Self::Czech),
            "english" => Some(Self::English),
            "french" => Some(Self::French),
            "italian" => Some(Self::Italian),
            "japanese" => Some(Self::Japanese),
            "korean" => Some(Self::Korean),
            "portuguese" => Some(Self::Portuguese),
            "spanish" => Some(Self::Spanish),
            _ => None,
        }
    }

    pub fn wordlist(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::ChineseSimplified => CHINESE_SIMPLIFIED.split_whitespace(),
            Self::ChineseTraditional => CHINESE_TRADITIONAL.split_whitespace(),
            Self::Czech => CZECH.split_whitespace(),
            Self::English => ENGLISH.split_whitespace(),
            Self::French => FRENCH.split_whitespace(),
            Self::Italian => ITALIAN.split_whitespace(),
            Self::Japanese => JAPANESE.split_whitespace(),
            Self::Korean => KOREAN.split_whitespace(),
            Self::Portuguese => PORTUGUESE.split_whitespace(),
            Self::Spanish => SPANISH.split_whitespace(),
        }
    }

    pub fn word_at(&self, index: usize) -> Option<&str> {
        if index < 2048 {
            Some(self.wordlist().nth(index).unwrap())
        } else {
            None
        }
    }

    pub fn index_of(&self, word: &str) -> Option<usize> {
        self.wordlist().position(|w| w == word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_length() {
        // words count
        for lang in Language::all() {
            assert_eq!(lang.wordlist().count(), 2048, "{lang:?}");
        }
    }

    #[test]
    fn test_language_repeat() {
        let mut repeats = Vec::new();
        let langs = Language::all();
        (0..langs.len()).for_each(|i| {
            (i + 1..langs.len()).for_each(|j| {
                let (x, y) = (langs[i], langs[j]);
                let n = x.wordlist().filter(|w| y.index_of(w).is_some()).count();
                if n > 0 {
                    repeats.push((x, y, n));
                }
            });
        });

        use Language::*;
        assert_eq!(repeats[0], (ChineseSimplified, ChineseTraditional, 1275));
        assert_eq!(repeats[1], (English, French, 100));
    }
}
