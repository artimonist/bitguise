#![cfg(test)]
use Language::*;
use disguise::Language;

#[test]
#[ignore = "pre test"]
fn language_common_count() {
    let mut repeats = Vec::new();
    let langs = Language::all();
    (0..langs.len()).for_each(|i| {
        (i + 1..langs.len()).for_each(|j| {
            let (x, y) = (langs[i], langs[j]);
            let n = x.word_list().filter(|w| y.index_of(w).is_some()).count();
            if n > 0 {
                repeats.push((x, y, n));
            }
        });
    });
    // common words count in different languages
    assert_eq!(repeats[0], (ChineseSimplified, ChineseTraditional, 1275));
    assert_eq!(repeats[1], (English, French, 100));
}

#[ignore = "pre test"]
#[test]
fn language_common_diff() {
    // test if two languages have different indices common words
    for (a, b) in [(ChineseSimplified, ChineseTraditional), (English, French)] {
        let mut diff = Vec::new();
        (0..2048).for_each(|i| {
            let word = a.word_at(i).unwrap();
            if let Some(j) = b.index_of(word) {
                if i != j {
                    diff.push((i, j, word));
                }
            }
        });
        // assert that the two languages have different indices common words
        if diff.len() > 0 {
            println!("{} and {} have {} different words:", a, b, diff.len());
            diff.iter().for_each(|(i, j, w)| {
                println!("  {i:4} {j:4} {w}");
            });
            assert!(false, "There are different words between {} and {}", a, b);
        }
    }
}

#[ignore = "pre test"]
#[test]
fn language_nfc_words() {
    use unicode_normalization::UnicodeNormalization;

    for lang in Language::all() {
        println!("{lang}");
        for word in lang.word_list() {
            let nfc: String = word.nfc().collect();
            if nfc != word {
                print!("{word} != {nfc}; ");
            }
        }
    }
}

#[test]
fn language_comman_mnemonic() {
    // test if a mnemonic has two language and verified checksum

    // all permutations mnemonic (12,15,18,21,24) in 100 English and French common words.
    // all permutations mnemonic (12,15,18,21,24) in 1275 Chinese common words.

    // assert_eq!(permutations!(3, 3).count(), 3_usize.pow(3));
    // assert_eq!(permutations!(3, 5).count(), 5_usize.pow(3));
    // assert_eq!(permutations!(3, 100).count(), 100_usize.pow(3));
    // assert_eq!(permutations!(12, 100).count(), 100_usize.pow(12));

    // It's too large, abandon.
}
