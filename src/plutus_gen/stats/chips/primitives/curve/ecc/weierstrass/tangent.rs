use super::super::super::sum_bigints;
use super::{
    WeierstrassColumnRanges, WeierstrassEmulationParams, WierstrassOpChipTrait, column_ranges,
    nb_advice_columns,
};

use crate::plutus_gen::stats::chips::curve::{
    count_non_trivial, count_non_zero, k_and_m_residues, non_trivial, non_zero, signed_mod,
};
use crate::plutus_gen::stats::chips::{Argument, Column, ScalarExpression};

use num_bigint::BigInt;
use num_traits::One;
use std::ops::Rem;

pub(crate) struct TangentChip;

impl TangentChip {
    fn bounds<Params: WeierstrassEmulationParams>() -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let moduli = Params::moduli();
        let bs = Params::base_powers();
        let bs2 = Params::double_base_powers();

        let a_plus_1 = signed_mod(&Params::a(), &Params::modulus()) + BigInt::one();

        let (limbs_max, limbs_max2) = Params::limb_bounds();
        let max_sum_px = sum_bigints(&bs, &limbs_max);
        let max_sum_py = max_sum_px.clone();
        let max_sum_lambda = max_sum_px.clone();
        let max_sum_px2 = sum_bigints(&bs2, &limbs_max2);
        let max_sum_lpy = max_sum_px2.clone();
        let expr_min = -BigInt::from(2) * (max_sum_py + max_sum_lambda + max_sum_lpy) + &a_plus_1;
        let expr_max = BigInt::from(3) * (&max_sum_px + &max_sum_px + max_sum_px2) + &a_plus_1;

        let expr_mj_bounds: Vec<_> = moduli
            .iter()
            .map(|mj| {
                let bs_mj = bs.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let bs2_mj = bs2.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let max_sum_px_mj = sum_bigints(&bs_mj, &limbs_max);
                let max_sum_py_mj = max_sum_px_mj.clone();
                let max_sum_lambda_mj = max_sum_px_mj.clone();
                let max_sum_px2_mj = sum_bigints(&bs2_mj, &limbs_max2);
                let max_sum_lpy_mj = max_sum_px2_mj.clone();
                let a_plus_1_mj = signed_mod(&a_plus_1, mj);
                let expr_mj_min = -BigInt::from(2)
                    * (max_sum_py_mj + max_sum_lambda_mj + max_sum_lpy_mj)
                    + &a_plus_1_mj;
                let expr_mj_max = BigInt::from(3)
                    * (&max_sum_px_mj + &max_sum_px_mj + max_sum_px2_mj)
                    + &a_plus_1_mj;
                (expr_mj_min, expr_mj_max)
            })
            .collect();

        Params::moduli_bounds(expr_min, expr_max, &expr_mj_bounds)
    }
}

impl<P: WeierstrassEmulationParams> WierstrassOpChipTrait<P> for TangentChip {
    fn advice() -> Vec<Column> {
        let nb_columns = nb_advice_columns::<P>();
        let mut columns: Vec<Column> = (0..nb_columns).map(|_| Column::empty_advice()).collect();

        let WeierstrassColumnRanges {
            x_cols,
            z_cols,
            u_col,
            v_cols,
            cond_col,
        } = column_ranges::<P>();

        // Base Field_chip copy constraints x_cols and z_cols
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());

        // cond_col queried at NEXT
        columns[cond_col].set_next();

        // x_cols queried at CURR and NEXT
        columns[x_cols.clone()].iter_mut().for_each(|c| {
            c.set_curr();
            c.set_next();
        });

        // z_cols queried at CURR
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_curr());

        // u_col set at NEXT
        columns[u_col].set_next();

        // v_cols set at NEXT
        columns[v_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_next());

        columns
    }

    fn extra_fixed() -> Vec<Column> {
        let mut columns = Vec::new();

        let q_tangent = Column::selector();

        columns.push(q_tangent);
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

        //   3 * (2 * sum_px + sum_px2) + 1
        // - 2 * (sum_py + sum_lambda + sum_lpy) = (u + k_min) * m
        let native = ScalarExpression::gate_expression(
            4,
            2,
            (bpl - 1) + 2 * dpl + 2 * bpl + 2 + non_zero(&k_min),
            0,
            1 + 2 * dpl + 2 * (dpl - 1) + 3 * (bpl - 1) + 5,
            2 * (dpl - 1) + 3 * (bpl - 1) + non_trivial(&k_min) + 5,
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

                let nb_neg = non_zero(&m_urem_mj) + non_zero(&k_min_m_urem_mj) + 2;
                let nb_add = (bi_non_zero - 1)
                    + 2 * bij_non_zero
                    + 2 * bi_non_zero
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + non_zero(&lj_min)
                    + 2;
                let nb_mul = 1
                    + 2 * bij_non_zero
                    + 2 * bij_non_trivial
                    + 3 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + 5;
                let nb_from_int = 2 * bij_non_trivial
                    + 3 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&k_min_m_urem_mj)
                    + non_trivial(&lj_min)
                    + 5;

                //   3 * (2 * sum_px_mj + sum_px2_mj) + 1
                // - 2 * (sum_py_mj + sum_lambda_mj + sum_lpy_mj)
                // - u * (m % mj) - (k_min * m) % mj - (vj + lj_min) * mj = 0
                let modulo_id =
                    ScalarExpression::gate_expression(4, nb_neg, nb_add, 0, nb_mul, nb_from_int);
                gate.push(modulo_id);
            });

        gates.push(gate);
        gates
    }
}
