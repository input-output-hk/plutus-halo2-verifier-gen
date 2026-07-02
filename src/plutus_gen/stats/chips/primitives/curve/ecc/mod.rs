use crate::plutus_gen::stats::chips::{
    Argument, Column, LookupTable, RotationSet, ScalarExpression, curve::FieldEmulationParams,
};

// Chips
mod lambda;
mod oncurve;
mod slope;
mod tangent;

use lambda::Lambda2Chip;
use oncurve::OnCurveChip;
use slope::SlopeChip;
use tangent::TangentChip;

use super::field::{FieldChip, FieldChipTrait};

// Params
pub(crate) mod params;
pub(crate) use params::EccEmulationParams;

// Operation chips needed to emulate an ECC
pub(super) trait EccOpChip<P: EccEmulationParams> {
    fn advice() -> Vec<Column>;
    fn extra_fixed() -> Vec<Column>;
    fn gates() -> Vec<Argument>;
}

pub struct EccChip {}
impl<P: FieldEmulationParams> FieldChipTrait<P> for EccChip {}
impl<P: EccEmulationParams> EccChipTrait<P> for EccChip {}

pub(crate) trait EccChipTrait<P: EccEmulationParams>: FieldChipTrait<P> {
    fn advice() -> Vec<Column> {
        let ecc_len = P::NB_LIMBS + std::cmp::max(P::NB_LIMBS, 2 + P::moduli().len()) + 1;
        let lambda2_advices = <Lambda2Chip as EccOpChip<P>>::advice();
        let oncurve_advices = <OnCurveChip as EccOpChip<P>>::advice();
        let slope_advices = <SlopeChip as EccOpChip<P>>::advice();
        let tangent_advices = <TangentChip as EccOpChip<P>>::advice();

        assert!(
            lambda2_advices.len() == ecc_len
                && oncurve_advices.len() == ecc_len
                && slope_advices.len() == ecc_len
                && tangent_advices.len() == ecc_len,
            "advice column count mismatch: expected={}, lambda2={}, oncurve={}, slope={}, tangent={}",
            ecc_len,
            lambda2_advices.len(),
            oncurve_advices.len(),
            slope_advices.len(),
            tangent_advices.len()
        );

        // Merging ECC columns
        let mut columns = lambda2_advices
            .into_iter()
            .zip(oncurve_advices)
            .zip(slope_advices)
            .zip(tangent_advices)
            .map(|(((l, o), s), t)| {
                let mut column = Column::empty_advice();
                column.merge_column(l);
                column.merge_column(o);
                column.merge_column(s);
                column.merge_column(t);
                column
            })
            .collect::<Vec<Column>>();

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

    fn extra_fixed() -> Vec<Column> {
        let base_fixed = <FieldChip as FieldChipTrait<P>>::extra_fixed();

        let lambda2_fixed = <Lambda2Chip as EccOpChip<P>>::extra_fixed();
        let oncurve_fixed = <OnCurveChip as EccOpChip<P>>::extra_fixed();
        let slope_fixed = <SlopeChip as EccOpChip<P>>::extra_fixed();
        let tangent_fixed = <TangentChip as EccOpChip<P>>::extra_fixed();

        // Creating extra selectors for lookups, we perform some lookup on the tag directly
        let q_multi_select = Column::complex_selector();
        let tag_col_multi_select = Column::exclusive_fixed(RotationSet::curr(), false);
        let own_fixed: Vec<Column> = vec![q_multi_select, tag_col_multi_select];

        [
            base_fixed,
            lambda2_fixed,
            oncurve_fixed,
            slope_fixed,
            tangent_fixed,
            own_fixed,
        ]
        .concat()
    }

    fn gates() -> Vec<Argument> {
        let base_args = <FieldChip as FieldChipTrait<P>>::gates();

        let lambda2_args = <Lambda2Chip as EccOpChip<P>>::gates();
        let oncurve_args = <OnCurveChip as EccOpChip<P>>::gates();
        let slope_args = <SlopeChip as EccOpChip<P>>::gates();
        let tangent_args = <TangentChip as EccOpChip<P>>::gates();

        [
            base_args,
            lambda2_args,
            oncurve_args,
            slope_args,
            tangent_args,
        ]
        .concat()
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
