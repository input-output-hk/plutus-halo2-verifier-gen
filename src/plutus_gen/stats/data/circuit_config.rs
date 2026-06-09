/// Extra circuit-level description for circuits not fully described by chips.
/// `nb_selectors` is kept separate from `nb_fixed` because selectors compile to fixed columns
/// in midnight-proofs (`directly_convert_selectors_to_fixed`) and must be counted in the VK.
#[derive(Default, Clone, Copy)]
pub struct CircuitConfig {
    pub nb_selectors: usize,
    pub nb_advice: usize,
    pub nb_fixed: usize,
    pub nb_evaluations: usize,
    pub nb_lookups: usize,
    pub degree: usize,
    pub nr_pow2range_cols: Option<usize>,
}

impl CircuitConfig {
    /// Creates a `CircuitConfig` with `nb_advice_evaluations` set explicitly when `Some`,
    /// or defaulting to `nb_advice` when `None` (i.e. every extra advice column is queried
    /// only at the current row).
    pub fn new(
        nb_selectors: usize,
        nb_advice: usize,
        nb_fixed: usize,
        nb_evaluations: Option<usize>,
        nb_lookups: usize,
        degree: usize,
        nr_pow2range_cols: Option<usize>,
    ) -> Self {
        Self {
            nb_selectors,
            nb_advice,
            nb_fixed,
            nb_evaluations: nb_evaluations.unwrap_or(nb_advice + nb_fixed),
            nb_lookups,
            degree,
            nr_pow2range_cols,
        }
    }
}
