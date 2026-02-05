//! Commitments type

use serde::{Deserialize, Serialize};

/// Commitments' types
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Commitments {
    Advice(usize),
    Fixed(usize),
    Permutation(char),
    PermutationsCommon(usize),
    VanishingG,
    VanishingRand,
    Lookup(usize),
    PermutedInput(usize),
    PermutedTable(usize),
}

impl Default for Commitments {
    fn default() -> Self {
        Commitments::Advice(0)
    }
}
