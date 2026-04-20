//! Evaluations type

use serde::{Deserialize, Serialize};

/// Evaluations' types
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub(crate) enum Evaluations {
    Instance(usize),
    Advice(usize),
    Fixed(usize),
    Permutation(char, usize),
    PermutationsCommon(usize),
    VanishingS,
    RandomEval,
    Lookup(usize),
    PermutedInput(usize),
    PermutedTable(usize),
    PermutedInputInverse(usize),
    LookupNext(usize),
    Trashcan(usize),
}

impl Default for Evaluations {
    fn default() -> Self {
        Evaluations::Advice(0)
    }
}
