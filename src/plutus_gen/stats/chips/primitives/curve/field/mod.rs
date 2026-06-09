use crate::plutus_gen::stats::chips::{Argument, Column};

// Chips
mod mul;
mod norm;

use mul::MulChip;
use norm::NormChip;

// Params
pub(crate) mod params;
pub(crate) use params::FieldEmulationParams;

// Operation chips needed to emulate a foreign Field
pub(super) trait FieldOpChip<P: FieldEmulationParams> {
    fn advice() -> Vec<Column>;
    fn extra_fixed() -> Vec<Column>;
    fn gates() -> Vec<Argument>;
}

// Scalar or Base field of an Elliptic curve
pub struct FieldChip;
impl<P: FieldEmulationParams> FieldChipTrait<P> for FieldChip {}

pub(crate) trait FieldChipTrait<P: FieldEmulationParams> {
    fn advice() -> Vec<Column> {
        let mul_advices = <MulChip as FieldOpChip<P>>::advice();
        let norm_advices = <NormChip as FieldOpChip<P>>::advice();

        assert!(mul_advices.len() == norm_advices.len());

        mul_advices
            .into_iter()
            .zip(norm_advices)
            .map(|(m, n)| {
                let mut column = Column::empty_advice();
                column.merge_column(m);
                column.merge_column(n);
                column
            })
            .collect::<Vec<Column>>()
    }

    fn extra_fixed() -> Vec<Column> {
        let mul_fixeds = <MulChip as FieldOpChip<P>>::extra_fixed();
        let norm_fixeds = <NormChip as FieldOpChip<P>>::extra_fixed();

        [mul_fixeds, norm_fixeds].concat()
    }
    fn gates() -> Vec<Argument> {
        let mul_args = <MulChip as FieldOpChip<P>>::gates();
        let norm_args = <NormChip as FieldOpChip<P>>::gates();
        [mul_args, norm_args].concat()
    }
}
