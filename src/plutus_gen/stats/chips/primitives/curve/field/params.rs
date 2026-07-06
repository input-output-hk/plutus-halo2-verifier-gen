use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::One;
use std::ops::Rem;

use ff::PrimeField;
use midnight_curves::bls12_381;

use super::super::{next_power_of_two, to_bigint, urem};

pub(crate) trait FieldEmulationParams {
    const LOG2_BASE: u32;
    const NB_LIMBS: usize;

    #[allow(unused)]
    const RC_LIMB_SIZE: usize;
    fn modulus() -> BigInt;
    fn moduli() -> Vec<BigInt>;

    fn moduli_bounds(
        lower_bound: BigInt,
        upper_bound: BigInt,
        mj_bounds: &[(BigInt, BigInt)],
    ) -> ((BigInt, BigInt), Vec<(BigInt, BigInt)>) {
        let native_modulus = to_bigint(bls12_381::Fq::MODULUS);
        let moduli: Vec<BigInt> = Self::moduli();
        let m = Self::modulus();

        let k_min = lower_bound.div_ceil(&m);
        let k_max = upper_bound.div_floor(&m);

        let u_max = next_power_of_two(&(&k_max - &k_min + BigInt::one()));

        let lower_bound = lower_bound - (&u_max + &k_min) * &m;
        let upper_bound = upper_bound - &k_min * &m;

        let mut necessary_moduli = vec![];
        let mut lcm = native_modulus.clone();
        for mj in moduli.iter() {
            if lcm > -&lower_bound && lcm > upper_bound {
                break;
            }
            lcm = lcm.lcm(mj);
            necessary_moduli.push(mj.clone());
        }
        if lcm <= -lower_bound || lcm <= upper_bound {
            panic!("lcm-threshold not reached, consider using extra auxiliary moduli")
        }

        let v_bounds = necessary_moduli
            .iter()
            .zip(mj_bounds.iter())
            .map(|(mj, (expr_mj_min, expr_mj_max))| {
                let k_min_m_mod_mj = urem(&(&k_min * &m), mj);
                let lj_min = (expr_mj_min - &u_max * urem(&m, mj) - &k_min_m_mod_mj).div_ceil(mj);
                let lj_max = (expr_mj_max - &k_min_m_mod_mj).div_floor(mj);

                let vj_max = next_power_of_two(&(&lj_max - &lj_min + BigInt::one()));

                let lower_bound = expr_mj_min
                    - &u_max * urem(&m, mj)
                    - &k_min_m_mod_mj
                    - (&vj_max + &lj_min) * mj;
                let upper_bound = expr_mj_max - &k_min_m_mod_mj - &lj_min * mj;

                if native_modulus <= -lower_bound || native_modulus <= upper_bound {
                    panic!("Moduli may wrap-around the native modulus")
                }
                (lj_min, vj_max)
            })
            .collect();
        ((k_min, u_max), v_bounds)
    }

    fn base_powers() -> Vec<BigInt> {
        let two = BigInt::from(2);
        let modulus = Self::modulus();
        (0..Self::NB_LIMBS as u32)
            .map(|i| two.pow(Self::LOG2_BASE * i).rem(&modulus))
            .collect()
    }

    fn double_base_powers() -> Vec<BigInt> {
        let two = BigInt::from(2);
        let modulus = Self::modulus();
        (0..Self::NB_LIMBS as u32)
            .flat_map(|i| {
                (0..Self::NB_LIMBS as u32)
                    .map(|j| two.pow(Self::LOG2_BASE * (i + j)).rem(&modulus))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn max_limb_bound() -> BigInt {
        BigInt::from(2).pow(2 * Self::LOG2_BASE)
    }

    /// The maximum value a single limb (`limbs_max`) or a pairwise product of
    /// two limbs (`limbs_max2`) can take, replicated once per limb / limb-pair
    /// position. Used by every gate's `bounds()` to size its worst-case sums.
    fn limb_bounds() -> (Vec<BigInt>, Vec<BigInt>) {
        let base = BigInt::from(2).pow(Self::LOG2_BASE);
        let limbs_max = vec![&base - BigInt::one(); Self::NB_LIMBS];
        let limbs_max2 = vec![(&base - BigInt::one()).pow(2); Self::NB_LIMBS * Self::NB_LIMBS];
        (limbs_max, limbs_max2)
    }
}
