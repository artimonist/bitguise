pub trait Permutation {
    fn permutations(&self, m: usize, n: usize) -> Box<dyn Iterator<Item = &Self> + '_>;
}

impl Permutation for std::cell::RefCell<Vec<usize>> {
    fn permutations(&self, m: usize, n: usize) -> Box<dyn Iterator<Item = &Self> + '_> {
        if self.borrow().len() < m {
            self.borrow_mut().resize(m, 0);
        }
        if m == 0 {
            Box::new(std::iter::once(self))
        } else {
            let iter = (0..n).flat_map(move |i| {
                self.borrow_mut()[m - 1] = i;
                self.permutations(m - 1, n)
            });
            Box::new(iter)
        }
    }
}

macro_rules! permutations {
    ($m:expr, $n:expr) => {
        std::cell::RefCell::new(vec![0; $m])
            .permutations($m, $n)
            .map(|v| v.borrow())
    };
}

pub(crate) use permutations;
