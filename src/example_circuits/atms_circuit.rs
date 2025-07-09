use atms_halo2::{
    ecc::chip::EccInstructions,
    instructions::MainGateInstructions,
    signatures::atms::{AtmsVerifierConfig, AtmsVerifierGate},
    signatures::schnorr::SchnorrSig,
    util::RegionCtx,
};
use blstrs::{Base, JubjubAffine};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone)]
pub struct BenchCircuitConfig {
    atms_config: AtmsVerifierConfig,
}

#[derive(Clone, Default)]
pub struct BenchCircuitAtmsSignature {
    pub signatures: Vec<Option<SchnorrSig>>,
    pub pks: Vec<JubjubAffine>,
    pub pks_comm: Base,
    pub msg: Base,
    pub threshold: Base,
}

impl Circuit<Base> for BenchCircuitAtmsSignature {
    type Config = BenchCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        let atms_config = AtmsVerifierGate::configure(meta);
        BenchCircuitConfig { atms_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Base>,
    ) -> Result<(), Error> {
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