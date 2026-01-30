//! Evaluations type

use serde::{Deserialize, Serialize};

/// Type listing all types of evaluations
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Evaluations {
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
}

impl Default for Evaluations {
    fn default() -> Self {
        Evaluations::Advice(0)
    }
}
