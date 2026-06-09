use super::super::sum_bigints;
use super::{FieldEmulationParams, FieldOpChip};

use crate::plutus_gen::stats::chips::curve::{non_trivial, non_zero, urem};
use crate::plutus_gen::stats::chips::{Argument, Column, ScalarExpression};

use num_bigint::BigInt;
use num_traits::One;
use std::ops::Rem;

pub(crate) struct MulChip;

impl MulChip {
    fn bounds<Params: FieldEmulationParams>() -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let base = BigInt::from(2).pow(Params::LOG2_BASE);
        let nb_limbs = Params::NB_LIMBS;
        let moduli = Params::moduli();
        let base_powers = Params::base_powers();
        let double_base_powers = Params::double_base_powers();

        let limbs_max = vec![&base - BigInt::one(); nb_limbs as usize];
        let limbs_max2 = vec![(&base - BigInt::one()).pow(2); (nb_limbs * nb_limbs) as usize];
        let max_sum_xy = sum_bigints(&double_base_powers, &limbs_max2);
        let max_sum_z = sum_bigints(&base_powers, &limbs_max);
        let max_sum_x = max_sum_z.clone();
        let max_sum_y = max_sum_z.clone();
        let expr_min = -max_sum_z;
        let expr_max = &max_sum_xy + &max_sum_x + &max_sum_y;

        let expr_mj_bounds: Vec<(BigInt, BigInt)> = moduli
            .iter()
            .map(|mj| {
                let base_powers_mj = base_powers.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let double_base_powers_mj = double_base_powers
                    .iter()
                    .map(|b| b.rem(mj))
                    .collect::<Vec<_>>();
                let max_sum_xy_mj = sum_bigints(&double_base_powers_mj, &limbs_max2);
                let max_sum_z_mj = sum_bigints(&base_powers_mj, &limbs_max);
                let max_sum_x_mj = max_sum_z_mj.clone();
                let max_sum_y_mj = max_sum_z_mj.clone();
                let expr_mj_min = -max_sum_z_mj;
                let expr_mj_max = &max_sum_xy_mj + &max_sum_x_mj + &max_sum_y_mj;
                (expr_mj_min, expr_mj_max)
            })
            .collect();

        Params::moduli_bounds(expr_min, expr_max, &expr_mj_bounds)
    }
}

impl<P: FieldEmulationParams> FieldOpChip<P> for MulChip {
    fn advice() -> Vec<Column> {
        let nb_columns = (2 * P::NB_LIMBS).max(P::NB_LIMBS + 1 + P::moduli().len());
        let mut columns: Vec<Column> = (0..nb_columns).map(|_| Column::empty_advice()).collect();

        let x_cols = 0..P::NB_LIMBS;
        // let y_cols = 0..P::NB_LIMBS;
        let z_cols = P::NB_LIMBS..(2 * P::NB_LIMBS);
        // let u_col = P::NB_LIMBS;
        // let v_cols = (P::NB_LIMBS + 1)..(P::NB_LIMBS + 1 + P::moduli().len());

        // Field_chip copy constraints x_cols and z_cols
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());

        // x_cols queried at CURR and NEXT
        columns[x_cols.clone()].iter_mut().for_each(|c| {
            c.set_curr();
            c.set_next();
        });

        // z_cols queried at CURR
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_curr());

        // z_cols[0] queried at NEXT
        columns[z_cols.start].set_next();

        // z_cols[1]..z_cols[vs_bounds.len()] set to NEXT
        let ((_k_min, _u_max), vs_bounds) = Self::bounds::<P>();
        columns[(z_cols.start + 1)..=(z_cols.start + vs_bounds.len())]
            .iter_mut()
            .for_each(|c| c.set_next());

        columns
    }

    fn extra_fixed() -> Vec<Column> {
        let mut columns = Vec::new();

        let q_mul = Column::selector();

        columns.push(q_mul);
        columns
    }

    fn gates() -> Vec<Argument> {
        let mut gates = Vec::new();
        let mut gate = Vec::new();

        let ((k_min, _u_max), vs_bounds) = Self::bounds::<P>();
        let dp = P::double_base_powers();
        let bp = P::base_powers();
        let m = P::modulus();

        let dpl = dp.len();
        let bpl = bp.len();

        //  sum_xy + sum_x + sum_y - sum_z - (u + k_min) * m = 0
        let native = ScalarExpression::gate_expression(
            3,
            2,
            (dpl - 1) + 3 * (bpl - 1) + 3 + 1 + non_zero(&k_min),
            0,
            1 + dpl + (dpl - 1) + 3 * (bpl - 1) + 1,
            (dpl - 1) + 3 * (bpl - 1) + non_trivial(&k_min) + 1,
        );
        gate.push(native);

        P::moduli()
            .iter()
            .zip(vs_bounds)
            .for_each(|(mj, bounds_j)| {
                let (lj_min, _vj_max) = bounds_j;
                let k_min_m_urem_mj = urem(&(&k_min * &m), &mj);
                let m_urem_mj = urem(&m, &mj);

                let bij_powers_mj: Vec<BigInt> = dp.iter().map(|b| b.rem(mj)).collect();
                let bi_powers_mj: Vec<BigInt> = bp.iter().map(|b| b.rem(mj)).collect();

                // We compute the number of coefficients that:
                // - are not 0s, so that we know we add the associated expression
                // - are neither 0s or 1s, so that we multiply the associated expression (by non trivial nb)
                let (bij_non_zero, bij_non_trivial) =
                    bij_powers_mj.iter().fold((0, 0), |(acc0, acc1), bij| {
                        (acc0 + non_zero(bij), acc1 + non_trivial(bij))
                    });
                let (bi_non_zero, bi_non_trivial) =
                    bi_powers_mj.iter().fold((0, 0), |(acc0, acc1), bi| {
                        (acc0 + non_zero(bi), acc1 + non_trivial(bi))
                    });

                let nb_neg = (bi_non_zero > 0) as usize
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + 1;
                let nb_add = (bij_non_zero - 1)
                    + 3 * bi_non_zero
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + non_zero(&lj_min)
                    + 1;
                let nb_mul = 1
                    + bij_non_trivial
                    + bij_non_zero
                    + 3 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + 1;
                let nb_from_int = bij_non_trivial
                    + 3 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&k_min_m_urem_mj)
                    + non_trivial(&lj_min)
                    + 1;

                //  sum_xy_mj + sum_x_mj + sum_y_mj - sum_z_mj - u * (m % mj) - (k_min * m) % mj
                //    - (vj + lj_min) * mj = 0
                let modulo_id =
                    ScalarExpression::gate_expression(3, nb_neg, nb_add, 0, nb_mul, nb_from_int);
                gate.push(modulo_id);
            });

        gates.push(gate);
        gates
    }
}
