use super::super::sum_bigints;
use super::{EccEmulationParams, EccOpChip, nb_advice_columns};

use crate::plutus_gen::stats::chips::curve::{non_trivial, non_zero, urem};
use crate::plutus_gen::stats::chips::{Argument, Column, ScalarExpression};

use num_bigint::BigInt;
use num_traits::One;
use std::ops::Rem;

pub(crate) struct SlopeChip;

impl SlopeChip {
    fn bounds<Params: EccEmulationParams>() -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let base = BigInt::from(2).pow(Params::LOG2_BASE);
        let nb_limbs = Params::NB_LIMBS;
        let moduli = Params::moduli();
        let bs = Params::base_powers();
        let bs2 = Params::double_base_powers();

        let limbs_max = vec![&base - BigInt::one(); nb_limbs];
        let limbs_max2 = vec![(&base - BigInt::one()).pow(2); nb_limbs * nb_limbs];
        let max_sum_px = sum_bigints(&bs, &limbs_max);
        let max_sum_py = max_sum_px.clone();
        let max_sum_qx = max_sum_px.clone();
        let max_sum_qy = max_sum_px.clone();
        let max_sum_lpx = sum_bigints(&bs2, &limbs_max2);
        let max_sum_lqx = max_sum_lpx.clone();
        let expr_min = -(BigInt::from(2) + &max_sum_qy + max_sum_py + max_sum_qx + max_sum_lqx);
        let expr_max = max_sum_qy + max_sum_px + max_sum_lpx;

        let expr_mj_bounds: Vec<_> = moduli
            .iter()
            .map(|mj| {
                let bs_mj = bs.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let bs2_mj = bs2.iter().map(|b| b.rem(mj)).collect::<Vec<_>>();
                let max_sum_px_mj = sum_bigints(&bs_mj, &limbs_max);
                let max_sum_py_mj = max_sum_px_mj.clone();
                let max_sum_qx_mj = max_sum_px_mj.clone();
                let max_sum_qy_mj = max_sum_px_mj.clone();
                let max_sum_lpx_mj = sum_bigints(&bs2_mj, &limbs_max2);
                let max_sum_lqx_mj = max_sum_lpx_mj.clone();
                let expr_mj_min = -(BigInt::from(2)
                    + &max_sum_qy_mj
                    + max_sum_py_mj
                    + max_sum_qx_mj
                    + max_sum_lqx_mj);
                let expr_mj_max = max_sum_qy_mj + max_sum_px_mj + max_sum_lpx_mj;
                (expr_mj_min, expr_mj_max)
            })
            .collect();

        Params::moduli_bounds(expr_min, expr_max, &expr_mj_bounds)
    }
}

impl<P: EccEmulationParams> EccOpChip<P> for SlopeChip {
    fn advice() -> Vec<Column> {
        let nb_columns = nb_advice_columns::<P>();
        let mut columns: Vec<Column> = (0..nb_columns).map(|_| Column::empty_advice()).collect();

        let x_cols = 0..P::NB_LIMBS;
        // let y_cols = 0..P::NB_LIMBS;
        let z_cols = P::NB_LIMBS..(2 * P::NB_LIMBS);
        let u_col = P::NB_LIMBS;
        let v_cols = (P::NB_LIMBS + 1)..(P::NB_LIMBS + 1 + P::moduli().len());
        let cond_col = x_cols.len() + v_cols.len() + 1;

        // Base Field_chip copy constraints x_cols and z_cols
        columns[x_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());
        columns[z_cols.clone()]
            .iter_mut()
            .for_each(|c| c.set_copy_constrained());

        // cond_col queried at NEXT
        columns[cond_col].set_next();

        // x_cols queried at PREV, CURR and NEXT
        columns[x_cols.clone()].iter_mut().for_each(|c| {
            c.set_prev();
            c.set_curr();
            c.set_next();
        });

        // z_cols queried at CURR
        columns[z_cols.clone()].iter_mut().for_each(|c| {
            c.set_prev();
            c.set_curr()
        });

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

        let q_slope = Column::selector();

        columns.push(q_slope);
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

        // sign - 1 + sign * sum_qy - sum_py - sum_qx + sum_px - sum_lqx + sum_lpx
        //  = (u + k_min) * m
        let native = ScalarExpression::gate_expression(
            4,
            5,
            2 * dpl + 4 * bpl + 2 + non_zero(&k_min),
            0,
            1 + 2 * dpl + 2 * (dpl - 1) + 4 * (bpl - 1) + 3,
            2 * (dpl - 1) + 4 * (bpl - 1) + non_trivial(&k_min) + 2,
        );
        gate.push(native);

        P::moduli()
            .iter()
            .zip(vs_bounds)
            .for_each(|(mj, bounds_j)| {
                let (lj_min, _vj_max) = bounds_j;
                let k_min_m_urem_mj = urem(&(&k_min * &m), mj);
                let m_urem_mj = urem(&m, mj);

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

                let nb_neg = non_zero(&m_urem_mj) + non_zero(&k_min_m_urem_mj) + 5;
                let nb_add = 2 * bij_non_zero
                    + 4 * bi_non_zero
                    + non_zero(&m_urem_mj)
                    + non_zero(&k_min_m_urem_mj)
                    + non_zero(&lj_min)
                    + 2;
                let nb_mul = 1
                    + 2 * bij_non_zero
                    + 2 * bij_non_trivial
                    + 4 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + 3;
                let nb_from_int = 2 * bij_non_trivial
                    + 4 * bi_non_trivial
                    + non_trivial(&m_urem_mj)
                    + non_trivial(&k_min_m_urem_mj)
                    + non_trivial(&lj_min)
                    + 2;

                // sign - 1 + sign * sum_qy_mj - sum_py_mj
                //  - sum_qx_mj + sum_px_mj - sum_lqx_mj + sum_lpx_mj
                //  - u * (m % mj) - (k_min * m) % mj - (vj + lj_min) * mj = 0
                let modulo_id =
                    ScalarExpression::gate_expression(2, nb_neg, nb_add, 0, nb_mul, nb_from_int);
                gate.push(modulo_id);
            });

        gates.push(gate);
        gates
    }
}
