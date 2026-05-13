use super::circuit_statistics::CircuitStatistics;

pub(crate) mod arith;
pub(crate) use arith::Arith;

pub(crate) mod schnorr_rescue_sidechain;
pub(crate) use schnorr_rescue_sidechain::SchnorrRescueSidechain;

/// A lookup table used by one or more chips.
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct LookupTable {
    pub name: &'static str,
    pub nb_columns: usize,
}

impl LookupTable {
    pub const fn new(name: &'static str, nb_columns: usize) -> Self {
        Self { name, nb_columns }
    }
}

#[derive(Clone, Copy)]
pub enum SupportedChips {
    Arith,
    SchnorrRescueSidechain,
    /// `nb_columns` lookup-table arguments contributed by this table.
    Lookup(LookupTable),
}

/// Returns a chip representing `nb_lookups` lookup-table arguments.
///
/// Pass the number of `meta.lookup(...)` calls this table contributes. `name` is ignored by
/// the estimator and is provided only for readability at the call site.
pub fn lookup_chip(name: &'static str, size: usize) -> SupportedChips {
    SupportedChips::Lookup(LookupTable::new(name, size))
}

/// Static descriptor for a concrete, single-purpose chip.
pub(crate) trait Chip {
    const NB_ADVICE: usize;
    const NB_FIXED: usize;
    const NB_EQUATIONS: usize;
    const DEGREE: usize;
    const NB_EVAL_POINTS: usize;
    const NB_LOOKUP_EXPRESSION_OPS: usize;
    /// Lookup tables this chip contributes. Empty for gate-only chips.
    const LOOKUP_TABLES: &'static [LookupTable] = &[];
    fn update_stats(&self, stats: &mut CircuitStatistics);
}

/// Runtime dispatcher over all supported chip variants.
impl SupportedChips {
    pub(crate) fn nb_advice(&self) -> usize {
        match self {
            Self::Arith => Arith::NB_ADVICE,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::NB_ADVICE,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn nb_fixed(&self) -> usize {
        match self {
            Self::Arith => Arith::NB_FIXED,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::NB_FIXED,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn nb_equations(&self) -> usize {
        match self {
            Self::Arith => Arith::NB_EQUATIONS,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::NB_EQUATIONS,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn nb_eval_points(&self) -> usize {
        match self {
            Self::Arith => Arith::NB_EVAL_POINTS,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::NB_EVAL_POINTS,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn nb_degree(&self) -> usize {
        match self {
            Self::Arith => Arith::DEGREE,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::DEGREE,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn nb_lookup_expression_ops(&self) -> usize {
        match self {
            Self::Arith => Arith::NB_LOOKUP_EXPRESSION_OPS,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::NB_LOOKUP_EXPRESSION_OPS,
            Self::Lookup(_) => 0,
        }
    }

    pub(crate) fn lookup_tables(&self) -> &[LookupTable] {
        match self {
            Self::Lookup(t) => std::slice::from_ref(t),
            Self::Arith => Arith::LOOKUP_TABLES,
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain::LOOKUP_TABLES,
        }
    }

    pub(crate) fn update_stats(&self, stats: &mut CircuitStatistics) {
        match self {
            Self::Arith => Arith.update_stats(stats),
            Self::SchnorrRescueSidechain => SchnorrRescueSidechain.update_stats(stats),
            Self::Lookup(_) => {}
        }
    }
}
