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

pub(crate) struct OnCurveChip;

impl OnCurveChip {
    fn bounds<Params: WeierstrassEmulationParams>() -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let moduli = Params::moduli();
        let bs = Params::base_powers();
        let bs2 = Params::double_base_powers();

        // (a+1)/(a+b) with a/b reduced to their signed representative closest
        // to zero. Needed for curves like secp256r1 where a = -3: the unsigned
        // residue p-3 would blow up the bounds.
        let m = Params::modulus();
        let a = signed_mod(&Params::a(), &m);
        let b = signed_mod(&Params::b(), &m);
        let a_plus_1 = &a + BigInt::one();
        let a_plus_b = &a + &b;

        let (limbs_max, limbs_max2) = Params::limb_bounds();
        let max_sum_x = sum_bigints(&bs, &limbs_max);
        let max_sum_y = max_sum_x.clone();
        let max_sum_z = max_sum_x.clone();
        let max_sum_xz = sum_bigints(&bs2, &limbs_max2);
        let max_sum_y2 = max_sum_xz.clone();

        let expr_min =
            -(&max_sum_xz + &max_sum_z + (&a_plus_1 * &max_sum_x).clone().max(BigInt::ZERO))
                - &a_plus_b;
        let expr_max = BigInt::from(2) * &max_sum_y + &max_sum_y2
            - (&a_plus_1 * &max_sum_x).min(BigInt::ZERO)
            - &a_plus_b;

        let expr_mj_bounds: Vec<_> = moduli
            .iter()
            .map(|mj| {
                let bs_mj = bs.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let bs2_mj = bs2.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let max_sum_x_mj = sum_bigints(&bs_mj, &limbs_max);
                let max_sum_y_mj = max_sum_x_mj.clone();
                let max_sum_z_mj = max_sum_x_mj.clone();
                let max_sum_xz_mj = sum_bigints(&bs2_mj, &limbs_max2);
                let max_sum_y2_mj = max_sum_xz_mj.clone();
                let a_plus_1_mj = signed_mod(&a_plus_1, mj);
                let a_plus_b_mj = signed_mod(&a_plus_b, mj);
                let a1_sum_x_mj = &a_plus_1_mj * &max_sum_x_mj;
                let expr_mj_min =
                    -(&max_sum_xz_mj + max_sum_z_mj + a1_sum_x_mj.clone().max(BigInt::from(0)))
                        - &a_plus_b_mj;
                let expr_mj_max = BigInt::from(2) * max_sum_y_mj + max_sum_y2_mj
                    - a1_sum_x_mj.min(BigInt::ZERO)
                    - &a_plus_b_mj;
                (expr_mj_min, expr_mj_max)
            })
            .collect();
        Params::moduli_bounds(expr_min, expr_max, &expr_mj_bounds)
    }
}

impl<P: WeierstrassEmulationParams> WierstrassOpChipTrait<P> for OnCurveChip {
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
        let y_cols = x_cols.clone();

        // Base Field_chip copy constraints x_cols and z_cols
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());

        // cond_col queried at NEXT
        columns[cond_col].set_next();

        // x_cols queried at CURR
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_curr());

        // y_cols queried at NEXT
        columns[y_cols.clone()].iter_mut().for_each(|c| {
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

        let q_on_curve = Column::selector();

        columns.push(q_on_curve);
        columns
    }

    fn gates() -> Vec<Argument> {
        let mut gates = Vec::new();
        let mut gate = Vec::new();

        let ((k_min, _u_max), vs_bounds) = Self::bounds::<P>();
        let dp = P::double_base_powers();
        let bp = P::base_powers();
        let m = P::modulus();
        let a = signed_mod(&P::a(), &m);
        let b = signed_mod(&P::b(), &m);
        let a_plus_1 = &a + BigInt::one();
        let a_plus_b = &a + &b;

        let dpl = dp.len();
        let bpl = bp.len();

        // 2 * sum_y + sum_y2 - (sum_xz + sum_z + (a + 1) * sum_x + (a + b))
        // = (u + k_min) * m
        let native = ScalarExpression::gate_expression(
            4,
            2,
            (bpl - 1) + 2 * dpl + 2 * bpl + 1 + non_zero(&k_min) + non_zero(&a_plus_b),
            0,
            1 + 2 * dpl + 2 * (dpl - 1) + 3 * (bpl - 1) + 3 + non_trivial(&a_plus_1),
            2 * (dpl - 1)
                + 3 * (bpl - 1)
                + non_trivial(&k_min)
                + 2
                + non_trivial(&a_plus_1)
                + non_trivial(&a_plus_b),
        );
        gate.push(native);

        P::moduli()
            .iter()
            .zip(vs_bounds)
            .for_each(|(mj, bounds_j)| {
                let (lj_min, _vj_max) = bounds_j;
                let (k_min_m_urem_mj, m_urem_mj) = k_and_m_residues(&k_min, &m, mj);
                let a_plus_1_mj = signed_mod(&a_plus_1, mj);
                let a_plus_b_mj = signed_mod(&a_plus_b, mj);

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
                    + (1 + non_zero(&a_plus_1_mj)) * bi_non_zero
                    + non_zero(&a_plus_b_mj)
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + non_zero(&a_plus_1_mj)
                    + non_zero(&lj_min);
                let nb_mul = 1
                    + 2 * bij_non_trivial
                    + 2 * bij_non_zero
                    + 3 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&a_plus_1_mj)
                    + 2
                    + (bi_non_zero > 0) as usize;
                let nb_from_int = 2 * bij_non_trivial
                    + 3 * bi_non_trivial
                    + non_trivial(&a_plus_b_mj)
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&k_min_m_urem_mj)
                    + non_trivial(&a_plus_1_mj)
                    + non_trivial(&lj_min)
                    + 2;

                // 2 * sum_y_mj + sum_y2_mj - (sum_xz_mj + sum_z_mj
                //  + signed_mod(a + 1, mj) * sum_x_mj + signed_mod(a + b, mj))
                //  - u * (m % mj) - (k_min * m) % mj - (vj + lj_min) * mj = 0
                let modulo_id =
                    ScalarExpression::gate_expression(4, nb_neg, nb_add, 0, nb_mul, nb_from_int);
                gate.push(modulo_id);
            });

        gates.push(gate);
        gates
    }
}
