use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// this example is based on halo2 book example that can be found here https://zcash.github.io/halo2/user/simple-example.html
// some parts are removed as this is a test example for code gen

#[derive(Clone, Debug)]
pub struct FieldConfig {
    advice: [Column<Advice>; 2],
    s_mul: Selector,
}

struct FieldChip<F: Field> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();
        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);
            vec![s_mul * (lhs * rhs - out)]
        });

        FieldConfig { advice, s_mul }
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: AssignedCell<F, F>,
        b: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                config.s_mul.enable(&mut region, 0)?;
                a.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;
                let value = a.value().copied() * b.value();
                region.assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
            },
        )
    }

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "private input", config.advice[0], 0, || value),
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region.assign_advice_from_constant(
                    || "constant value",
                    config.advice[0],
                    0,
                    constant,
                )
            },
        )
    }
}

#[derive(Default, Debug)]
pub struct MyCircuit<F: Field> {
    constant: F,
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

impl<F: Field> MyCircuit<F> {
    pub fn init(constant: F, a: F, b: F, c: F) -> MyCircuit<F> {
        MyCircuit {
            constant,
            a: Value::known(a),
            b: Value::known(b),
            c: Value::known(c),
        }
    }
}
impl<F: Field> Circuit<F> for MyCircuit<F> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        // Create a column to load public inputs, they are not used in this example
        // but in general I want to export public instances along with the proof
        // so it is added
        let _instance = meta.instance_column();

        FieldChip::configure(meta, advice, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<F>::construct(config);

        // Load our private values into the circuit.
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = field_chip.load_private(layouter.namespace(|| "load c"), self.c)?;

        // Load the constant factor into the circuit.
        let constant =
            field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

        let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;
        let c_out = field_chip.mul(layouter.namespace(|| "constant * absq"), constant, absq)?;

        layouter.assign_region(
            || "Assert equality",
            |mut region| region.constrain_equal(c_out.cell(), c.cell()),
        )
    }
}
