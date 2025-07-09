use atms_halo2::{
    ecc::chip::EccInstructions,
    instructions::MainGateInstructions,
    signatures::atms::{AtmsVerifierConfig, AtmsVerifierGate},
    signatures::schnorr::SchnorrSig,
    util::RegionCtx,
};
use atms_halo2::rescue::{RescueParametersBls, RescueSponge};
use atms_halo2::signatures::primitive::schnorr::Schnorr;
use blstrs::{Base, JubjubAffine};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::prelude::{IteratorRandom, StdRng};

#[derive(Clone)]
pub struct AtmsConfig {
    atms_config: AtmsVerifierConfig,
}

#[derive(Clone, Default)]
pub struct AtmsSignatureCircuit {
    pub signatures: Vec<Option<SchnorrSig>>,
    pub pks: Vec<JubjubAffine>,
    pub pks_comm: Base,
    pub msg: Base,
    pub threshold: Base,
}

impl Circuit<Base> for AtmsSignatureCircuit {
    type Config = AtmsConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        let atms_config = AtmsVerifierGate::configure(meta);
        AtmsConfig { atms_config }
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

/// Generates `num_parties` random key pairs, `threshold` number signatures forv `msg`, and Merkle Tree commitment to public keys
/// Returns:
///     `threshold` number of signatures for `msg`
///     `num_parties` public keys
///     MT commitment to public keys
pub fn prepare_test_signatures(
    num_parties: usize,
    threshold: usize,
    msg: Base,
    rng: &mut StdRng,
) -> (Vec<Option<SchnorrSig>>, Vec<JubjubAffine>, Base) {
    let keypairs = (0..num_parties)
        .map(|_| Schnorr::keygen(rng))
        .collect::<Vec<_>>();

    let pks = keypairs.iter().map(|(_, pk)| *pk).collect::<Vec<_>>();

    let mut flattened_pks = std::vec::Vec::with_capacity(keypairs.len() * 2);
    for (_, pk) in &keypairs {
        flattened_pks.push(pk.get_u());
    }

    let pks_comm = RescueSponge::<Base, RescueParametersBls>::hash(&flattened_pks, None);

    let signing_parties = (0..num_parties).choose_multiple(rng, threshold);
    let signatures = (0..num_parties)
        .map(|index| {
            if signing_parties.contains(&index) {
                Some(Schnorr::sign(keypairs[index], msg, rng))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (signatures, pks, pks_comm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use blstrs::Base;
    use halo2_proofs::plonk::k_from_circuit;
    use rand::SeedableRng;

    #[test]
    fn test_atms_circuit() {
        // const NUM_PARTIES: usize = 2001; // todo: multiple of three so Rescue does not complain. We should do some padding
        // const THRESHOLD: usize = 1602;

        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);
        let (signatures, pks, pks_comm) =
            prepare_test_signatures(NUM_PARTIES, THRESHOLD, msg, &mut rng);

        let circuit = AtmsSignatureCircuit {
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