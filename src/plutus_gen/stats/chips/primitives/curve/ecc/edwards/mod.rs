use crate::plutus_gen::stats::chips::{
    Argument, Column, LookupTable, RotationSet, ScalarExpression, curve::FieldEmulationParams,
};

// Chips
mod addition;
use addition::AdditionChip;

use super::super::field::{FieldChip, FieldChipTrait};

// Params
pub(crate) mod params;
pub(crate) use params::EdwardsEmulationParams;

// Operation chips needed to emulate an ECC
pub(super) trait EdwardsOpChipTrait<P: EdwardsEmulationParams> {
    fn advice() -> Vec<Column>;
    fn fixed() -> Vec<Column>;
    fn extra_fixed() -> Vec<Column>;
    fn gates() -> Vec<Argument>;
}

/// Number of advice columns each `EdwardsOpChip` (addition) allocates.
pub(super) fn nb_advice_columns<P: EdwardsEmulationParams>() -> usize {
    P::NB_LIMBS + std::cmp::max(P::NB_LIMBS, 1 + P::moduli().len()) + 1
}

/// Column-index ranges shared by every `EdwardsOpChip` (currently just
/// addition, but kept alongside `WeierstrassColumnRanges` for consistency
/// should a second Edwards op-chip be added later).
pub(super) struct EdwardsColumnRanges {
    pub(super) x_cols: std::ops::Range<usize>,
    pub(super) z_cols: std::ops::Range<usize>,
    pub(super) u_col: usize,
    pub(super) v_cols: std::ops::Range<usize>,
}

pub(super) fn column_ranges<P: EdwardsEmulationParams>() -> EdwardsColumnRanges {
    let x_cols = 0..P::NB_LIMBS;
    let z_cols = P::NB_LIMBS..(2 * P::NB_LIMBS);
    let u_col = P::NB_LIMBS;
    let v_cols = (P::NB_LIMBS + 1)..(P::NB_LIMBS + 1 + P::moduli().len());
    EdwardsColumnRanges {
        x_cols,
        z_cols,
        u_col,
        v_cols,
    }
}

pub struct EdwardsChip {}
impl<P: FieldEmulationParams> FieldChipTrait<P> for EdwardsChip {}
impl<P: EdwardsEmulationParams> EdwardsChipTrait<P> for EdwardsChip {}

pub(crate) trait EdwardsChipTrait<P: EdwardsEmulationParams>: FieldChipTrait<P> {
    fn advice() -> Vec<Column> {
        let ecc_len = nb_advice_columns::<P>();
        let mut columns = <AdditionChip as EdwardsOpChipTrait<P>>::advice();

        assert!(
            columns.len() == ecc_len,
            "advice column count mismatch: expected={}, addition={}",
            ecc_len,
            columns.len()
        );

        let base_advices = <FieldChip as FieldChipTrait<P>>::advice();
        assert!(
            base_advices.len() <= ecc_len,
            "More BaseField columns than expected: {} not lower than {}",
            base_advices.len(),
            ecc_len
        );
        // Merging base columns
        base_advices
            .into_iter()
            .enumerate()
            .for_each(|(i, b)| columns[i].merge_column(b));

        // TODO: this should be the last column given to the chip, there may be more than the ones needed (need to know from other chips used).
        assert!(columns.len() > 2 * P::NB_LIMBS);

        // index of the last column
        let idx_col_multi_select = columns.len() - 1;
        columns[idx_col_multi_select].set_copy_constrained();

        // Lookups query following columns to CURR
        columns[idx_col_multi_select].set_curr();
        columns[0..P::NB_LIMBS]
            .iter_mut()
            .for_each(|c| c.set_curr()); // x_cols
        columns[P::NB_LIMBS..2 * P::NB_LIMBS]
            .iter_mut()
            .for_each(|c| c.set_curr()); // z_cols

        columns
    }

    fn fixed() -> Vec<Column> {
        let columns = <AdditionChip as EdwardsOpChipTrait<P>>::fixed();

        columns
    }

    fn extra_fixed() -> Vec<Column> {
        let base_fixed = <FieldChip as FieldChipTrait<P>>::extra_fixed();

        let addition_fixed = <AdditionChip as EdwardsOpChipTrait<P>>::extra_fixed();

        // Creating extra selectors for lookups, we perform some lookup on the tag directly
        let q_multi_select = Column::complex_selector();
        let tag_col_multi_select = Column::exclusive_fixed(RotationSet::curr(), false);
        let own_fixed: Vec<Column> = vec![q_multi_select, tag_col_multi_select];

        [base_fixed, addition_fixed, own_fixed].concat()
    }

    fn gates() -> Vec<Argument> {
        let base_args = <FieldChip as FieldChipTrait<P>>::gates();

        let addition_args = <AdditionChip as EdwardsOpChipTrait<P>>::gates();

        [base_args, addition_args].concat()
    }

    // As we lookup on a fixed column, there is no lookup tables
    fn lookup_tables() -> Vec<LookupTable> {
        vec![]
    }

    fn lookups() -> Vec<Argument> {
        let mut args: Vec<Argument> = Vec::new();
        let mut arg: Argument = Vec::new();

        // identities on idx_col_multi_select, x_cols and z_cols
        (0..(1 + 2 * P::NB_LIMBS)).for_each(|_| {
            // (val.clone(), not_sel.clone() * val) where not_sel = (1-q_multi_select)
            let lookup = ScalarExpression::lookup_expression(2, 1, 1, 1, 0, 1, 1);
            arg.push(lookup);
        });

        // similar lookup but on tag: (tag.clone(), not_sel * tag)
        arg.push(ScalarExpression::lookup_expression(2, 1, 1, 1, 0, 1, 1));

        args.push(arg);
        args
    }
}
