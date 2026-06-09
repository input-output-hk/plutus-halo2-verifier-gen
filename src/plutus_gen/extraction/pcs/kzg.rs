//! Module for extracting the Halo2 variant of KZG PCS' steps and data.
use crate::plutus_gen::extraction::data::{CircuitRepresentation, CommitmentData};

use super::{CircuitStatistics, ExtractPCS, PCSType};

use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::KZGCommitmentScheme;

use itertools::Itertools;

type Halo2MultiOpenScheme = KZGCommitmentScheme<Bls12>;

/// Halo2 Multi-Open PCS data comprises the number of q evaluations only.
#[derive(Default)]
pub struct HMOData {
    q_evaluations_count: usize,
}

/// The Halo2 Multi-Open PCS steps comprise five challenge generation (x1 to x4
/// and pi) and the handling of the f commitment and the q evaluations.
#[derive(PartialEq, Clone, Debug)]
pub enum HMOSteps {
    X1,
    X2,
    X3,
    X4,
    PI,
    QEvals,
    FCommitment,
}

impl ExtractPCS for Halo2MultiOpenScheme {
    type PCSExtractionSteps = HMOSteps;
    type PCSData = HMOData;
    fn pcs_type() -> PCSType {
        PCSType::Halo2MultiOpen
    }

    fn pcs_data(circuit_repr: &CircuitRepresentation<Self>) -> usize {
        circuit_repr.pcs_instantiation_data.q_evaluations_count
    }

    fn pcs_data_aiken(circuit_repr: &CircuitRepresentation<Self>) -> String {
        (1..=circuit_repr.pcs_instantiation_data.q_evaluations_count)
            .map(|n| format!("q_eval_on_x3_{}", n))
            .join(", ")
    }

    fn pcs_data_plinth(circuit_repr: &CircuitRepresentation<Self>) -> String {
        (1..=circuit_repr.pcs_instantiation_data.q_evaluations_count)
            .map(|n| format!("q_eval_on_x3_{}", n))
            .join(", ")
    }

    fn extract_pcs(circuit_repr: &mut CircuitRepresentation<Self>) {
        circuit_repr.pcs_extraction_steps.push(HMOSteps::X1);

        circuit_repr.pcs_extraction_steps.push(HMOSteps::X2);

        circuit_repr
            .pcs_extraction_steps
            .push(HMOSteps::FCommitment);

        circuit_repr.pcs_extraction_steps.push(HMOSteps::X3);

        // number of final witnesses is equal to number of different point sets
        let (sets, _) = Self::precompute_intermediate_sets(circuit_repr);
        let number_of_witnesses = sets.len();
        circuit_repr.pcs_instantiation_data.q_evaluations_count = number_of_witnesses;

        // witnesses
        for _ in 0..number_of_witnesses {
            circuit_repr.pcs_extraction_steps.push(HMOSteps::QEvals);
        }

        circuit_repr.pcs_extraction_steps.push(HMOSteps::X4);

        circuit_repr.pcs_extraction_steps.push(HMOSteps::PI);
    }

    fn step_to_aiken(step: Self::PCSExtractionSteps, number: usize) -> String {
        match step {
            HMOSteps::X1 => {
                "    let (x1, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            HMOSteps::X2 => {
                "    let (x2, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            HMOSteps::X3 => {
                "    let (x3, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            HMOSteps::X4 => {
                "    let (x4, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            HMOSteps::PI => "    let (pi_term, _) =  read_point(transcript)\n".to_string(),
            HMOSteps::FCommitment => {
                "    let (f_commitment, transcript) =  read_point(transcript)\n".to_string()
            }
            HMOSteps::QEvals => format!(
                "    let (q_eval_on_x3_{}, transcript) = read_scalar(transcript)\n",
                number
            ),
        }
    }

    fn step_to_plinth(step: Self::PCSExtractionSteps, number: usize) -> String {
        match step {
            HMOSteps::X1 => "  !x1 <- M.squeezeChallenge\n".to_string(),
            HMOSteps::X2 => "  !x2 <- M.squeezeChallenge\n".to_string(),
            HMOSteps::X3 => "  !x3 <- M.squeezeChallenge\n".to_string(),
            HMOSteps::X4 => "  !x4 <- M.squeezeChallenge\n".to_string(),
            HMOSteps::PI => "  !pi_term <- M.readPoint\n".to_string(),
            HMOSteps::FCommitment => "  !f_commitment <- M.readPoint\n".to_string(),
            HMOSteps::QEvals => format!("  !q_eval_on_x3_{} <- M.readScalar\n", number),
        }
    }

    fn step_stat_operation(stats: &mut CircuitStatistics, step: &Self::PCSExtractionSteps) {
        match step {
            HMOSteps::X1 => stats.squeeze_challenge(),
            HMOSteps::X2 => stats.squeeze_challenge(),
            HMOSteps::X3 => stats.squeeze_challenge(),
            HMOSteps::X4 => stats.squeeze_challenge(),
            HMOSteps::PI => stats.read_point(),
            HMOSteps::FCommitment => stats.read_point(),
            HMOSteps::QEvals => stats.read_scalar(),
        }
    }

    fn step_stat(step: &Self::PCSExtractionSteps) -> (usize, usize) {
        match step {
            HMOSteps::PI => (1, 0),
            HMOSteps::FCommitment => (1, 0),
            HMOSteps::QEvals => (0, 1),
            _ => (0, 0),
        }
    }

    fn opening_stat(stats: &mut CircuitStatistics, circuit: &CircuitRepresentation<Self>) {
        let (unique_grouped_points, commitment_data) = Self::precompute_intermediate_sets(circuit);

        let halo2_commitment_data: Vec<Vec<usize>> = (0..unique_grouped_points.len())
            .map(|idx| {
                let commitments_in_set: Vec<&CommitmentData> = commitment_data
                    .iter()
                    .filter(|&cd| cd.point_set_index == idx)
                    .collect();

                commitments_in_set
                    .into_iter()
                    .map(|cd| cd.evaluations.len())
                    .collect::<Vec<usize>>()
            })
            .collect::<Vec<Vec<usize>>>();
        let max_commitments_per_points_set = halo2_commitment_data
            .iter()
            .map(|commitments| commitments.len())
            .max()
            .unwrap_or(0);

        let kzg_halo2_point_sets = unique_grouped_points
            .iter()
            .map(|set| set.len())
            .collect::<Vec<usize>>();
        let point_sets_indexes = unique_grouped_points.len();

        // Computing powers of x1 (max points per set)
        (0..max_commitments_per_points_set).for_each(|_| stats.mul_scalar()); // powers of x1

        // Computng powers of x4 (num point sets)
        (0..point_sets_indexes + 1).for_each(|_| stats.mul_scalar()); // powers of x4

        // Compute Q evaluations and final commitment
        compute_q_evals(stats, &halo2_commitment_data);

        // Compute f evaluation
        compute_f_eval(stats, &kzg_halo2_point_sets);

        // Compute v evaluation
        compute_v_eval(stats, point_sets_indexes);

        // Compressing commitment
        (0..2).for_each(|_| stats.add_point());
        (0..2).for_each(|_| stats.scale());
        (0..2).for_each(|_| stats.decompress_point());
    }
}

fn compute_q_evals(stats: &mut CircuitStatistics, halo2_commitment_data: &Vec<Vec<usize>>) {
    let mut is_first = true;
    for commitment_set in halo2_commitment_data {
        stats.msm(commitment_set.len());
        for eval in commitment_set {
            // This is a fold so there is a difference for decompress/add/mul of 1 for the init
            // Accumulator1: let acc1 = add_g1(acc1, scale(decompress(commitment), x1Power))
            stats.decompress_point();

            // Accumulator2: if is_empty(acc2) {map(es, fn(e) { mul(e, x1Power) })} else {map2(acc2, es, fn(a, b) { add(a, mul(b, x1Power)) })}
            (0..*eval).for_each(|_| {
                stats.mul_scalar();
                if !is_first {
                    stats.add_scalar();
                }
                is_first = false;
            });
        }

        //  let acc1 = add_g1(acc1, scale(q_comms, x4Power))
        stats.add_point();
        stats.scale();
    }
}

fn compute_f_eval(stats: &mut CircuitStatistics, kzg_halo2_point_sets: &Vec<usize>) {
    // Before CIP:
    {
        // step 1: compute r_evals and demonimator for all point sets
        kzg_halo2_point_sets.iter().for_each(|nb_rot| {
            // let r_eval = lagrange_evaluation(zip(points, evals), x3)
            stats.lagrange_evaluation(*nb_rot);

            // denom
            (0..*nb_rot).for_each(|_| {
                stats.sub_scalar();
                stats.mul_scalar();
            });
        });

        // step 2: batch inverse
        // TODO when CIP-109 is implemented, inverting each element should be cheaper
        stats.batch_inversion(kzg_halo2_point_sets.len());

        // step 3: compute final result
        kzg_halo2_point_sets.iter().for_each(|_| {
            // let evaluation = mul(sub(proofQEval, r_eval), denom_inv)
            stats.mul_scalar();
            stats.sub_scalar();

            // add(mul(acc_eval, x2), evaluation)
            stats.mul_scalar();
            stats.add_scalar();
        });
    }

    // // After CIP:
    // {
    //     kzg_halo2_point_sets.iter().for_each(|nb_rot| {
    //         {
    //             // let r_eval = lagrange_evaluation(zip(points, evals), x3)
    //             stats.lagrange_evaluation(*nb_rot);

    //             // Computing denominator
    //             (0..*nb_rot).for_each(|_| {
    //                 stats.sub_scalar();
    //                 stats.mul_scalar();
    //             });

    //             // let evaluation = mul(sub(proofQEval, r_eval), denominator)
    //             stats.sub_scalar();
    //             stats.mul_scalar();

    //             // add(mul(acc_eval, x2), evaluation)
    //             stats.mul_scalar();
    //             stats.add_scalar();
    //         }
    //     });
    // }
}

fn compute_v_eval(stats: &mut CircuitStatistics, point_sets_indexes: usize) {
    (0..point_sets_indexes).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });
}
