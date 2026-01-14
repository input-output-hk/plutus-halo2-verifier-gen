use ff::PrimeField;
use midnight_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use midnight_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector, TableColumn,
};
use midnight_proofs::poly::Rotation;
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Clone, Default)]
pub struct LookupTest<F: PrimeField> {
    // config: Pow2RangeConfig,
    pub inputs: Vec<(u64, usize)>, // (values, bit_len)
    pub max_bit_len: usize,
    pub native_field: PhantomData<F>,
}

/// Number of check lookup columns
pub const NB_POW2RANGE_COLS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pow2RangeConfig {
    instance: Column<Instance>,
    q_pow2range: Selector,
    tag_col: Column<Fixed>,
    /// The columns where the range-checked values are placed.
    val_cols: [Column<Advice>; NB_POW2RANGE_COLS],
    // fixed columns of lookup table
    t_tag: TableColumn,
    t_val: TableColumn,
}

impl<F: PrimeField> Circuit<F> for LookupTest<F> {
    type Config = Pow2RangeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let columns = (0..NB_POW2RANGE_COLS)
            .map(|_| {
                let col = meta.advice_column();
                meta.enable_equality(col);
                col
            })
            .collect::<Vec<_>>();
        let instance = meta.instance_column();
        // meta.enable_equality(instance);
        let q_pow2range = meta.complex_selector();
        let tag_col = meta.fixed_column();
        let t_tag = meta.lookup_table_column();
        let t_val = meta.lookup_table_column();

        let val_cols: [Column<Advice>; NB_POW2RANGE_COLS] = columns[..NB_POW2RANGE_COLS]
            .try_into()
            .expect("wrong number of columns");

        for val_col in val_cols {
            meta.lookup("pow2range column check", |meta| {
                let sel = meta.query_selector(q_pow2range);
                let tag = meta.query_fixed(tag_col, Rotation::cur());
                let val = meta.query_advice(val_col, Rotation::cur());
                vec![(tag, t_tag), (sel * val, t_val)]
            });
        }

        Pow2RangeConfig {
            instance,
            q_pow2range,
            tag_col,
            val_cols,
            t_tag,
            t_val,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "pow2range table",
            |mut table| {
                let mut offset = 0;
                for bit_len in 0..=self.max_bit_len {
                    let tag = Value::known(F::from(bit_len as u64));
                    for value in 0..(1 << bit_len) {
                        let val = Value::known(F::from(value));
                        table.assign_cell(|| "t_tag", config.t_tag, offset, || tag)?;
                        table.assign_cell(|| "t_val", config.t_val, offset, || val)?;
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
                    let col = config.val_cols[0];
                    let val = Value::known(F::from(input.0));

                    let assigned_val =
                        region.assign_advice(|| "pow2range val", col, offset, || val)?;

                    let chunk = &[assigned_val];

                    // Assign the chunk of values at the current offset.
                    for (assigned, col) in chunk.iter().zip(config.val_cols.iter()) {
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
                            config.val_cols[i],
                            offset,
                            || Value::known(F::ZERO),
                        )?;
                    }
                    if input.1 > self.max_bit_len {
                        panic!(
                            "assert_row_lower_than_2_pow_n: n={} cannot exceed max_bit_len={}",
                            input.1, self.max_bit_len
                        )
                    }
                    config.q_pow2range.enable(&mut region, offset)?;
                    region.assign_fixed(
                        || "pow2range_tag",
                        config.tag_col,
                        offset,
                        || Value::known(F::from(input.1 as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::lookup_table_circuit::LookupTest;
    use midnight_curves::{Base, BlsScalar as Scalar};

    use midnight_proofs::dev::MockProver;
    use midnight_proofs::plonk::k_from_circuit;
    use std::marker::PhantomData;

    #[test]
    fn test_lookup_circuit() {
        let circuit = LookupTest::<Scalar> {
            inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
            max_bit_len: 9,
            native_field: PhantomData,
        };

        let pi = vec![vec![
            Base::from(42u64),
            Base::from(42u64),
            Base::from(42u64),
        ]];

        let k: u32 = k_from_circuit(&circuit);
        let prover =
            MockProver::run(k, &circuit, pi).expect("Failed to run ATMS verifier mock prover");

        prover.assert_satisfied();
    }
}
