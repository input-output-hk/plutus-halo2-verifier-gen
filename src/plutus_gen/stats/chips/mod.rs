use std::cmp::max;
use std::collections::BTreeSet;

pub(crate) mod primitives;
pub(crate) use primitives::*;

pub(crate) mod types;
pub(crate) use types::{
    column::Column,
    expression::{Argument, ScalarExpression},
    lookup_table::LookupTable,
    rotation_set::RotationSet,
    scalar_ops::ScalarOps,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, strum::EnumIter, strum::Display)]
pub enum SupportedChips {
    #[strum(to_string = "native")]
    Native,
    #[strum(to_string = "poseidon")]
    Poseidon,
    // Blake2b,
    // Sha3256,
    // Keccak256,
    #[strum(to_string = "sha256")]
    Sha256,
    #[strum(to_string = "sha512")]
    Sha512,
    #[strum(to_string = "htc")]
    HashToCurve,
    #[strum(to_string = "curve25519")]
    Curve25519,
    #[strum(to_string = "jubjub")]
    EdwardsJubjub,
    #[strum(to_string = "bls12381")]
    WeierstrassBls12381,
    #[strum(to_string = "secp256k1")]
    WeierstrassSecp256k1,
    // WeierstrassSecp256r1,
    #[strum(disabled)]
    P2RDecomposition(usize),
    // Automaton,
    // Base64,
    #[strum(disabled)]
    VerifierGadget,
    #[strum(disabled)]
    Lookup(LookupTable),
}

/// Returns a chip representing `nb_arguments` lookup-table arguments with only Table columns.
///
/// `name` is ignored by the estimator and is provided only for readability at the call site.
pub fn lookup_chip(
    name: String,
    nb_arguments: usize,
    input_degree: usize,
    table_degree: usize,
) -> SupportedChips {
    SupportedChips::Lookup(LookupTable::new(
        name,
        1,
        max(1, nb_arguments),
        max(1, input_degree),
        max(1, table_degree),
    ))
}

/// Static descriptor for a concrete, single-purpose chip.
pub(crate) trait Chip {
    /// Advice columns (`ColumnType::Advice`).
    fn advice_columns() -> Vec<Column> {
        vec![]
    }

    /// Shared fixed columns (`ColumnType::SharedFixed`).
    fn fixed_columns() -> Vec<Column> {
        vec![]
    }

    /// Everything else: selectors, complex selectors, exclusive fixed, table columns.
    fn extra_columns() -> Vec<Column> {
        vec![]
    }

    /// Gates expressions **this chip** contributes (`meta.create_gate()` calls)
    fn gate_args() -> Vec<Argument> {
        vec![]
    }

    /// Lookup tables **this chip** contributes.
    fn lookup_tables() -> Vec<LookupTable> {
        vec![]
    }

    /// Lookup expressions **this chip** contributes (`meta.lookup()` or `meta.lookup_any()`).
    // 1 argument per meta.lookup() comprising one ScalarExpression per item in the tuple
    // e.g.  vec![(tag, t_tag), (sel * val, t_val)] is an argument of 2 ScalarExpressions:
    // 1) table: tag,   input: sel * val
    // 2) table: t_tag, input: t_val
    fn lookup_args() -> Vec<Argument> {
        vec![]
    }

    /// Trashcan expressions **this chip** contributes (`Constraints::with_additive_selector()`).
    fn trash_args() -> Vec<Argument> {
        vec![]
    }

    /// Direct sub-chips whose columns and gates this chip subsumes. `flatten_chips` resolves
    /// these transitively and deduplicates, ensuring each chip (including shared bases like
    /// `Native`) is counted exactly once regardless of how many composites declare it.
    fn chip_deps() -> Vec<SupportedChips> {
        vec![]
    }

    /// Number of pow2range columns best suited for the chip. Default 0.
    fn nr_pow2range() -> usize {
        0
    }
}

/// Generates the `impl SupportedChips` block from a list of `Variant => ChipType` pairs.
///
/// For each variant the macro reads the chip's associated constants and dispatches
/// `update_stats`. The `Lookup` variant is handled with fixed inline defaults for every
/// generated method: `&[]` / `0` for most fields, `1` for `nb_lookup_expression_ops`,
/// and `std::slice::from_ref(t)` for `lookup_tables`.
/// Adding a new chip only requires one line in the invocation below.
macro_rules! impl_supported_chips {
    ($($variant:ident => $chip:path),+ $(,)?) => {
        impl SupportedChips {
            pub(crate) fn advice(&self) -> Vec<Column> {
                match self {
                    $(Self::$variant => <$chip>::advice_columns(),)+
                    Self::Lookup(_) => vec![],
                    Self::P2RDecomposition(_) => P2RDecomposition::advice_columns(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn fixed(&self) -> Vec<Column> {
                match self {
                    $(Self::$variant => <$chip>::fixed_columns(),)+
                    Self::Lookup(_) => vec![],
                    Self::P2RDecomposition(_) => P2RDecomposition::fixed_columns(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn extra_fixed(&self) -> Vec<Column> {
                match self {
                    $(Self::$variant => <$chip>::extra_columns(),)+
                    Self::Lookup(l) => {
                        let col = Column::exclusive_fixed(RotationSet::curr(), false);
                        vec![col; l.nb_columns]
                    },
                    Self::P2RDecomposition(_) => P2RDecomposition::extra_columns(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn degree(&self) -> usize {
                match self {
                    $(Self::$variant => <$chip>::gate_args().iter().chain(<$chip>::lookup_args().iter().chain(<$chip>::trash_args().iter())).map(|group_exp| group_exp.iter().map(|exp| exp.degree).max().unwrap_or(1)).max().unwrap_or(1),)+
                    Self::Lookup(l) => max(4, 2 + l.input_degree + l.table_degree),
                    Self::P2RDecomposition(_) => P2RDecomposition::gate_args().iter().chain(P2RDecomposition::lookup_args().iter().chain(P2RDecomposition::trash_args().iter())).map(|group_exp| group_exp.iter().map(|exp| exp.degree).max().unwrap_or(1)).max().unwrap_or(1),
                    Self::VerifierGadget => 0
                }
            }

            pub(crate) fn gates(&self) -> Vec<Vec<ScalarExpression>> {
                match self {
                    $(Self::$variant => <$chip>::gate_args(),)+
                    Self::Lookup(_) => vec![],
                    Self::P2RDecomposition(_) => P2RDecomposition::gate_args(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn nb_lookup_args(&self) -> usize {
                match self {
                    $(Self::$variant => <$chip>::lookup_args().len(),)+
                    Self::Lookup(l) => l.nb_arguments,
                    Self::P2RDecomposition(n) => n * P2RDecomposition::lookup_args().len(),
                    Self::VerifierGadget => 0
                }
            }

            pub(crate) fn lookups(&self) -> Vec<Vec<ScalarExpression>> {
                match self {
                    $(Self::$variant => <$chip>::lookup_args(),)+
                    Self::Lookup(l) => {
                        let se = ScalarExpression {degree : self.degree(), ops: ScalarOps::default()};
                        vec![vec![se; l.nb_arguments]]
                    },
                    Self::P2RDecomposition(n) => {
                        let args = P2RDecomposition::lookup_args();
                        (0..*n).flat_map(|_| args.clone()).collect()
                    }
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn nb_trashcan_args(&self) -> usize {
                match self {
                    $(Self::$variant => <$chip>::trash_args().len(),)+
                    Self::Lookup(_) => 0,
                    Self::P2RDecomposition(_) => P2RDecomposition::trash_args().len(),
                    Self::VerifierGadget => 0
                }
            }

            pub(crate) fn trashcans(&self) -> Vec<Vec<ScalarExpression>> {
                match self {
                    $(Self::$variant => <$chip>::trash_args(),)+
                    Self::Lookup(_) => vec![],
                    Self::P2RDecomposition(_) => P2RDecomposition::trash_args(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn lookup_tables(&self) -> Vec<LookupTable> {
                match self {
                    Self::Lookup(t) => vec![t.clone()],
                    $(Self::$variant => <$chip>::lookup_tables(),)+
                    Self::P2RDecomposition(_) => P2RDecomposition::lookup_tables(),
                    Self::VerifierGadget => vec![]
                }
            }

            pub(crate) fn chip_deps(&self) -> Vec<SupportedChips> {
                match self {
                    $(Self::$variant => <$chip>::chip_deps(),)+
                    Self::Lookup(_) => vec![],
                    Self::P2RDecomposition(_) => vec![],
                    Self::VerifierGadget => VerifierGadget::chip_deps()
                }
            }

            pub(crate) fn nr_pow2range_cols(&self) -> usize {
                match self {
                    $(Self::$variant => <$chip>::nr_pow2range(),)+
                    Self::Lookup(_) => 0,
                    Self::P2RDecomposition(n) => *n,
                    Self::VerifierGadget => VerifierGadget::nr_pow2range()
                }
            }
        }
    }
}

impl_supported_chips! {
    Native               => Native,
    Poseidon             => Poseidon,
    Sha256               => Sha256,
    Sha512               => Sha512,
    // Keccak256           => Keccak256, // 3rd party impl
    // Sha3256           => Sha3256, // 3rd party impl
    // Blake2b              => Blake2b, // 3rd party impl
    HashToCurve         => HashToCurve,
    Curve25519          => Curve25519,
    EdwardsJubjub        => EdwardsJubjub,
    WeierstrassBls12381  => WeierstrassBls12381,
    WeierstrassSecp256k1 => WeierstrassSecp256k1,
    // WeierstrassSecp256r1 => WeierstrassSecp256r1,
    // Automaton            => Automaton,
    // Base64               => Base64,
}

/// Flattens `chips` and all their transitive `CHIP_DEPS` into a deduplicated set.
/// Each chip appears at most once, so shared deps like `Native` are counted once
/// regardless of how many composites in the input declare them.
pub(crate) fn flatten_chips(chips: &[SupportedChips]) -> BTreeSet<SupportedChips> {
    let mut set = BTreeSet::new();
    let mut queue = chips.to_vec();
    while let Some(chip) = queue.pop() {
        let deps = chip.chip_deps();
        if set.insert(chip) {
            queue.extend(deps);
        }
    }
    set
}

pub(crate) fn flatten_tables(chips: &[SupportedChips]) -> BTreeSet<LookupTable> {
    flatten_chips(chips)
        .iter()
        .flat_map(|chip| chip.lookup_tables())
        .collect()
}

pub(crate) fn merge_chips_advice(chips: &BTreeSet<SupportedChips>) -> Vec<Column> {
    let all_advices: Vec<Vec<Column>> = chips.iter().map(|c| c.advice()).collect();
    let max_advice = all_advices.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut advices = Vec::new();
    for _ in 0..max_advice {
        advices.push(Column::empty_advice());
    }
    for columns in all_advices {
        for (i, col) in columns.into_iter().enumerate() {
            advices[i].merge_column(col);
        }
    }

    advices
}

pub(crate) fn merge_chips_fixed(chips: &BTreeSet<SupportedChips>) -> Vec<Column> {
    let mut all = Vec::new();

    // Merging all shared fixed columns
    let all_fixed: Vec<Vec<Column>> = chips.iter().map(|c| c.fixed()).collect();
    let max_fixed = all_fixed.iter().map(|r| r.len()).max().unwrap_or(0);

    for _ in 0..max_fixed {
        all.push(Column::empty_shared());
    }
    for columns in all_fixed {
        for (i, col) in columns.into_iter().enumerate() {
            all[i].merge_column(col);
        }
    }

    // Adding all extra columns
    let extras: Vec<Vec<Column>> = chips.iter().map(|c| c.extra_fixed()).collect();
    for columns in extras {
        for col in columns {
            all.push(col);
        }
    }

    all
}
