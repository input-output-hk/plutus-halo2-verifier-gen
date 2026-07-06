use super::super::super::sum_bigints;
use super::{
    EdwardsColumnRanges, EdwardsEmulationParams, EdwardsOpChipTrait, column_ranges,
    nb_advice_columns,
};

use crate::plutus_gen::stats::chips::curve::{
    count_non_trivial, count_non_zero, k_and_m_residues, non_trivial, non_zero,
};
use crate::plutus_gen::stats::chips::{Argument, Column, RotationSet, ScalarExpression};

use num_bigint::BigInt;
use std::ops::Rem;

pub(crate) struct AdditionChip;

impl AdditionChip {
    fn bounds<Params: EdwardsEmulationParams>() -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let moduli = Params::moduli();
        let bs = Params::base_powers();
        let bs2 = Params::double_base_powers();

        let (limbs_max, limbs_max_sqrd) = Params::limb_bounds();

        let max_sum = sum_bigints(&bs, &limbs_max);
        let max_sum_sqrd = sum_bigints(&bs2, &limbs_max_sqrd);

        let expr_min = -(BigInt::from(2) * &max_sum + &max_sum_sqrd + BigInt::from(2));
        let expr_max = BigInt::from(3) * &max_sum + &max_sum_sqrd;

        let expr_mj_bounds: Vec<_> = moduli
            .iter()
            .map(|mj| {
                let bs_mj = bs.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let bs_sqrd_mj = bs2.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();

                let max_sum_mj = sum_bigints(&bs_mj, &limbs_max);
                let max_sum_sqrd_mj = sum_bigints(&bs_sqrd_mj, &limbs_max_sqrd);

                let expr_min_mj =
                    -(BigInt::from(2) * &max_sum_mj + &max_sum_sqrd_mj + BigInt::from(2));
                let expr_max_mj = BigInt::from(3) * &max_sum_mj + &max_sum_sqrd_mj;
                (expr_min_mj, expr_max_mj)
            })
            .collect();

        Params::moduli_bounds(expr_min, expr_max, &expr_mj_bounds)
    }
}

impl<P: EdwardsEmulationParams> EdwardsOpChipTrait<P> for AdditionChip {
    fn advice() -> Vec<Column> {
        let nb_columns = nb_advice_columns::<P>();
        let mut columns: Vec<Column> = (0..nb_columns).map(|_| Column::empty_advice()).collect();

        let EdwardsColumnRanges {
            x_cols,
            z_cols,
            u_col,
            v_cols,
        } = column_ranges::<P>();

        // Base Field_chip copy constraints x_cols and z_cols
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());

        // x_cols queried at PREV, CURR and NEXT
        columns[x_cols.clone()].iter_mut().for_each(|c| {
            c.set_prev();
            c.set_curr();
            c.set_next();
        });

        // z_cols queried at PREV
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_prev());

        // u_col set at NEXT
        columns[u_col].set_next();

        // v_cols set at NEXT
        columns[v_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_next());

        columns
    }

    fn fixed() -> Vec<Column> {
        // sign column
        let sign_col = Column::shared_fixed(RotationSet::curr(), false);
        vec![sign_col]
    }

    fn extra_fixed() -> Vec<Column> {
        let mut columns = Vec::new();

        let q_add = Column::selector();

        columns.push(q_add);
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

        // (1 + s) * sum_x + s * (sum_w + sum_xw) - sum_y - sum_z + (s-1)
        //  = (u + k_min) * m
        let native = ScalarExpression::gate_expression(
            3,
            4,
            dpl + 4 * bpl + 8 + non_zero(&k_min),
            0,
            1 + dpl + (dpl - 1) + 4 * (bpl - 1) + 3,
            (dpl - 1) + 4 * (bpl - 1) + non_trivial(&k_min) + 3,
        );
        gate.push(native);

        P::moduli()
            .iter()
            .zip(vs_bounds)
            .for_each(|(mj, bounds_j)| {
                let (lj_min, _vj_max) = bounds_j;
                let (k_min_m_urem_mj, m_urem_mj) = k_and_m_residues(&k_min, &m, mj);

                // We compute the number of coefficients that:
                // - are not 0s, so that we know we add the associated expression
                // - are neither 0s or 1s, so that we multiply the associated expression (by non trivial nb)
                let bij_non_zero = count_non_zero(&dp, mj);
                let bij_non_trivial = count_non_trivial(&dp, mj);
                let bi_non_zero = count_non_zero(&bp, mj);
                let bi_non_trivial = count_non_trivial(&bp, mj);

                let nb_neg = non_zero(&m_urem_mj) + non_zero(&k_min_m_urem_mj) + 4;
                let nb_add = bij_non_zero
                    + 4 * bi_non_zero
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + non_zero(&lj_min)
                    + 3;
                let nb_mul = 1
                    + bij_non_zero
                    + bij_non_trivial
                    + 4 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + 2;
                let nb_from_int = bij_non_trivial
                    + 4 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&k_min_m_urem_mj)
                    + non_trivial(&lj_min)
                    + 3;

                let modulo_id =
                    ScalarExpression::gate_expression(4, nb_neg, nb_add, 0, nb_mul, nb_from_int);
                gate.push(modulo_id);
            });

        gates.push(gate);
        gates
    }
}
