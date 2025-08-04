/// Example circuit implementing ATMS signature verification and a lookup table.
/// The lookup table does not serve a functional purpose and is included only to evaluate
/// the complexity of Plutus verification for this type of circuit.
use atms_halo2::{
    ecc::chip::EccInstructions,
    instructions::MainGateInstructions,
    signatures::atms::{AtmsVerifierConfig, AtmsVerifierGate},
    signatures::schnorr::SchnorrSig,
    util::RegionCtx,
};
use blstrs::{Base, JubjubAffine};
use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn,
};
use halo2_proofs::poly::Rotation;
use std::convert::TryInto;

#[derive(Clone, Default)]
pub struct AtmsLookupCircuit {
    //pow2 range check inputs (for lookup)
    pub inputs: Vec<(u64, usize)>, // (values, bit_len)
    pub max_bit_len: usize,

    // atms inputs
    pub signatures: Vec<Option<SchnorrSig>>,
    pub pks: Vec<JubjubAffine>,
    pub pks_comm: Base,
    pub msg: Base,
    pub threshold: Base,
}

/// Number of check lookup columns
pub const NB_POW2RANGE_COLS: usize = 1;
// pub const NB_POW2RANGE_COLS: usize = 4;

#[derive(Clone, Debug)]
pub struct AtmsLookupConfig {
    pow2_range_config: Pow2RangeConfig,
    atms_config: AtmsVerifierConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pow2RangeConfig {
    //instance: Column<Instance>,
    q_pow2range: Selector,
    tag_col: Column<Fixed>,
    /// The columns where the range-checked values are placed.
    val_cols: [Column<Advice>; NB_POW2RANGE_COLS],
    // fixed columns of lookup table
    t_tag: TableColumn,
    t_val: TableColumn,
}

impl Circuit<Base> for AtmsLookupCircuit {
    type Config = AtmsLookupConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        let atms_config = AtmsVerifierGate::configure(meta);

        let columns = (0..NB_POW2RANGE_COLS)
            .map(|_| {
                let col = meta.advice_column();
                meta.enable_equality(col);
                col
            })
            .collect::<Vec<_>>();

        ///////// let instance = meta.instance_column();
        ///////// meta.enable_equality(instance);
        let q_pow2range = meta.complex_selector();
        let tag_col = meta.fixed_column();
        let t_tag = meta.lookup_table_column();
        let t_val = meta.lookup_table_column();

        let val_cols: [Column<Advice>; NB_POW2RANGE_COLS] =
            columns[..NB_POW2RANGE_COLS].try_into().unwrap();

        for val_col in val_cols {
            meta.lookup("pow2range column check", |meta| {
                let sel = meta.query_selector(q_pow2range);
                let tag = meta.query_fixed(tag_col, Rotation::cur());
                let val = meta.query_advice(val_col, Rotation::cur());
                vec![(tag, t_tag), (sel * val, t_val)]
            });
        }

        let pow2_range_config = Pow2RangeConfig {
            //instance,
            q_pow2range,
            tag_col,
            val_cols,
            t_tag,
            t_val,
        };

        AtmsLookupConfig {
            pow2_range_config,
            atms_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Base>,
    ) -> Result<(), Error> {
        // Lookup related synthesis
        layouter.assign_table(
            || "pow2range table",
            |mut table| {
                let mut offset = 0;
                for bit_len in 0..=self.max_bit_len {
                    let tag = Value::known(Base::from(bit_len as u64));
                    for value in 0..(1 << bit_len) {
                        let val = Value::known(Base::from(value));
                        table.assign_cell(
                            || "t_tag",
                            config.pow2_range_config.t_tag,
                            offset,
                            || tag,
                        )?;
                        table.assign_cell(
                            || "t_val",
                            config.pow2_range_config.t_val,
                            offset,
                            || val,
                        )?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )?;

        // todo check offsets, as it was incremented 2 times before next iteration
        layouter.assign_region(
            || "pow2range test",
            |mut region| {
                let iter: Vec<_> = (0..).step_by(2).zip(self.inputs.iter()).collect();
                for (offset, input) in iter {
                    let col = config.pow2_range_config.val_cols[0];
                    let val = Value::known(Base::from(input.0));

                    let assigned_val =
                        region.assign_advice(|| "pow2range val", col, offset, || val)?;

                    let chunk = &[assigned_val];

                    // Assign the chunk of values at the current offset.
                    for (assigned, col) in
                        chunk.iter().zip(config.pow2_range_config.val_cols.iter())
                    {
                        let x = region.assign_advice(
                            || "pow2range val",
                            *col,
                            offset,
                            || assigned.value().copied(),
                        )?;
                        region.constrain_equal(x.cell(), assigned.cell())?
                    }
                    // Assign zeros in the unassigned lookup columns in case |chunk| <
                    // NB_POW2RANGE_COLS.
                    for i in chunk.len()..NB_POW2RANGE_COLS {
                        region.assign_advice(
                            || "pow2range zero",
                            config.pow2_range_config.val_cols[i],
                            offset,
                            || Value::known(Base::ZERO),
                        )?;
                    }
                    if input.1 > self.max_bit_len {
                        panic!(
                            "assert_row_lower_than_2_pow_n: n={} cannot exceed max_bit_len={}",
                            input.1, self.max_bit_len
                        )
                    }
                    config
                        .pow2_range_config
                        .q_pow2range
                        .enable(&mut region, offset)?;
                    region.assign_fixed(
                        || "pow2range_tag",
                        config.pow2_range_config.tag_col,
                        offset,
                        || Value::known(Base::from(input.1 as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // ATMS related synthesis
        let atms_gate = AtmsVerifierGate::new(config.atms_config);

        let pi_values = layouter.assign_region(
            || "ATMS verifier test",
            |region| {
                let offset = 0;
                let mut ctx = RegionCtx::new(region, offset);
                let assigned_sigs = self
                    .signatures
                    .iter()
                    .map(|&signature| {
                        if let Some(sig) = signature {
                            Some(
                                atms_gate
                                    .schnorr_gate
                                    .assign_sig(&mut ctx, &Value::known(sig))
                                    .ok()?,
                            )
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let assigned_pks = self
                    .pks
                    .iter()
                    .map(|&pk| {
                        atms_gate
                            .schnorr_gate
                            .ecc_gate
                            .witness_point(&mut ctx, &Value::known(pk))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                // We assign cells to be compared against the PI
                let pi_cells = atms_gate
                    .schnorr_gate
                    .ecc_gate
                    .main_gate
                    .assign_values_slice(
                        &mut ctx,
                        &[
                            Value::known(self.pks_comm),
                            Value::known(self.msg),
                            Value::known(self.threshold),
                        ],
                    )?;

                atms_gate.verify(
                    &mut ctx,
                    &assigned_sigs,
                    &assigned_pks,
                    &pi_cells[0],
                    &pi_cells[1],
                    &pi_cells[2],
                )?;

                Ok(pi_cells)
            },
        )?;

        let ecc_gate = atms_gate.schnorr_gate.ecc_gate;

        layouter.constrain_instance(pi_values[0].cell(), ecc_gate.instance_col(), 0)?;

        layouter.constrain_instance(pi_values[1].cell(), ecc_gate.instance_col(), 1)?;

        layouter.constrain_instance(pi_values[2].cell(), ecc_gate.instance_col(), 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::atms_circuit::prepare_test_signatures;
    use blstrs::Base;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::k_from_circuit;
    use rand::SeedableRng;
    use rand::prelude::StdRng;

    #[test]
    fn test_circuit() {
        // const NUM_PARTIES: usize = 2001; // todo: multiple of three so Rescue does not complain. We should do some padding
        // const THRESHOLD: usize = 1602;

        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);
        let (signatures, pks, pks_comm) =
            prepare_test_signatures(NUM_PARTIES, THRESHOLD, msg, &mut rng);

        let circuit = AtmsLookupCircuit {
            // lookup fields
            inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
            max_bit_len: 9,

            // atms fields
            signatures,
            pks,
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi = vec![vec![pks_comm, msg, Base::from(THRESHOLD as u64)]];

        let k: u32 = k_from_circuit(&circuit);
        let prover =
            MockProver::run(k, &circuit, pi).expect("Failed to run ATMS verifier mock prover");

        prover.assert_satisfied();
    }
}
