/// Cost breakdown of a scalar expression.
#[derive(Default, Debug, Clone, Copy)]
pub struct ScalarOps {
    pub nb_neg: usize,
    pub nb_add: usize,
    pub nb_sub: usize,
    pub nb_mul: usize,
    pub nb_from_int: usize,
}

impl ScalarOps {
    pub(crate) fn new(neg: usize, add: usize, sub: usize, mul: usize, from_int: usize) -> Self {
        Self {
            nb_neg: neg,
            nb_add: add,
            nb_sub: sub,
            nb_mul: mul,
            nb_from_int: from_int,
        }
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        Self {
            nb_neg: self.nb_neg + other.nb_neg,
            nb_add: self.nb_add + other.nb_add,
            nb_sub: self.nb_sub + other.nb_sub,
            nb_mul: self.nb_mul + other.nb_mul,
            nb_from_int: self.nb_from_int + other.nb_from_int,
        }
    }
}
