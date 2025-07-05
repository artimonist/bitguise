#![cfg(test)]
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

    let vec = std::cell::RefCell::new(vec![0; 3]);
    for p in vec.permutations(3, 3) {
        println!("{:?}", p);
    }
    assert_eq!(vec.permutations(3, 3).count(), 3_usize.pow(3));
}

use std::cell::{Ref, RefCell};
type VecRef<'a> = Ref<'a, Vec<usize>>;
type VecIterator<'a> = Box<dyn Iterator<Item = VecRef<'a>> + 'a>;

trait Permutation {
    fn permutations(&self, m: usize, n: usize) -> VecIterator<'_>;
}

impl Permutation for RefCell<Vec<usize>> {
    fn permutations(&self, m: usize, n: usize) -> VecIterator<'_> {
        debug_assert!(
            m <= self.borrow().len(),
            "m must be less than or equal to the length of the vector"
        );

        if m == 0 {
            Box::new([self.borrow()].into_iter())
        } else {
            let iter = (0..n).flat_map(move |i| {
                self.borrow_mut()[m - 1] = i;
                self.permutations(m - 1, n)
            });
            Box::new(iter)
        }
    }
}
