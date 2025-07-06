#![cfg(test)]
mod common;

use common::{Permutation, permutations};
use disguise::Language;

#[test]
fn test_language_common() {
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
    // common words in different languages
    use Language::*;
    assert_eq!(repeats[0], (ChineseSimplified, ChineseTraditional, 1275));
    assert_eq!(repeats[1], (English, French, 100));
}

#[test]
fn test_mnemonic_common() {
    // test if a mnemonic has two language and verified checksum

    // all permutations mnemonic (12,15,18,21,24) in 100 English and French common words.
    // all permutations mnemonic (12,15,18,21,24) in 1275 Chinese common words.

    assert_eq!(permutations!(3, 3).count(), 3_usize.pow(3));
    assert_eq!(permutations!(3, 5).count(), 5_usize.pow(3));
    assert_eq!(permutations!(3, 100).count(), 100_usize.pow(3));
    // assert_eq!(permutations!(12, 100).count(), 100_usize.pow(12));

    // It's too large, abandon.
}
