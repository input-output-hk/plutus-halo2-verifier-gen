use std::collections::{BTreeMap, BTreeSet};

use super::chips::flatten_tables;
use super::chips::types::expression::ScalarExpression;
use super::chips::types::scalar_ops::ScalarOps;
use super::estimate::proof::estimate_proof_size;
use super::estimate::vk::estimate_vk_size;
use super::pcs::PcsEstimate;
use crate::plutus_gen::stats::{
    arguments::permutation::permutation_query_rotations,
    arguments::vanishing::vanishing_query_rotations,
    chips::{
        Argument, RotationSet, SupportedChips, flatten_chips, merge_chips_advice, merge_chips_fixed,
    },
    estimate::build::compute_degree,
    lookup::{LookupEstimate, PlookUp},
};

fn fold_args(args: &[Vec<ScalarExpression>]) -> ScalarOps {
    args.iter()
        .map(|arg| ScalarExpression::batch_expressions(arg.clone()).ops)
        .fold(ScalarOps::default(), |acc, ops| acc.add(&ops))
}

/// Chip cost profile for the web cost explorer.
#[derive(serde::Serialize)]
///
/// Computed via `process` with pi=1, ci=0, no extra columns.
/// `chip_cc` is the number of copy-constrained columns the chip contributes,
/// excluding the instance column (which depends on the caller's pi/ci).
pub struct ChipProfile {
    pub deps: Vec<String>,
    pub degree: usize,
    pub advice_cols: usize,
    pub fixed_cols: usize,
    pub copy_constraints: usize,
    pub nb_lookup_tables: usize,
    pub gates: usize,
    pub lookups: usize,
    pub trash: usize,
    pub evals: usize,
    pub gate_ops: ScalarOps,
    pub lookup_ops: ScalarOps,
    pub trash_ops: ScalarOps,
    pub commitment_map: Vec<Vec<usize>>,
    pub proof_size: usize,
    pub vk_size: usize,
}

pub fn chip_profile<PCS: PcsEstimate>(chip: SupportedChips) -> ChipProfile {
    let chips = flatten_chips(std::slice::from_ref(&chip));
    let tables = flatten_tables(std::slice::from_ref(&chip));

    let mut deps = chips.clone();
    deps.remove(&chip);
    let deps: Vec<String> = deps.iter().map(|c| c.to_string()).collect();

    let advice_cols = merge_chips_advice(&chips);
    let fixed_cols = merge_chips_fixed(&chips);

    let nb_copy_constrained = advice_cols
        .iter()
        .chain(fixed_cols.iter())
        .map(|col| col.is_copy_constrained() as usize)
        .sum();
    let nb_advice = advice_cols.len();
    let nb_fixed = fixed_cols.len();

    let lookup_args: Vec<Argument> = chips.iter().flat_map(|c| c.lookups()).collect();
    let nb_lookups = lookup_args.len();

    let trashcan_args: Vec<Argument> = chips.iter().flat_map(|c| c.trashcans()).collect();
    let nb_trashcans = trashcan_args.len();

    let circuit_degree = compute_degree(0, nb_copy_constrained, nb_lookups, nb_trashcans, &chips);

    let gate_args: Vec<Argument> = chips.iter().flat_map(|c| c.gates()).collect();
    let nb_gates = gate_args.len();

    // Creating permutation queries
    let permutation_queries = permutation_query_rotations(nb_copy_constrained, circuit_degree);

    // Creating vanishing queries
    let vanishing_queries = vanishing_query_rotations();

    // Creating lookup queries
    let mut lookup_queries = Vec::new();
    (0..nb_lookups).for_each(|_| {
        lookup_queries.extend(PlookUp::lookup_poly_rotations());
    });

    // Creating trashcan queries
    let mut trashcan_queries = BTreeSet::new();
    (0..nb_trashcans).for_each(|_| {
        trashcan_queries.insert(RotationSet::curr());
    });

    let advice_queries = advice_cols
        .iter()
        .map(|col| col.rotations())
        .collect::<Vec<RotationSet>>();
    let fixed_queries = fixed_cols
        .iter()
        .map(|col| col.rotations())
        .collect::<Vec<RotationSet>>();
    let nb_evaluations = advice_queries.len() + fixed_queries.len();

    let queries = advice_queries
        .into_iter()
        .chain(fixed_queries)
        .chain(permutation_queries)
        .chain(vanishing_queries)
        .chain(lookup_queries)
        .chain(trashcan_queries)
        .collect::<Vec<_>>();

    let mut query_args_map: BTreeMap<RotationSet, usize> = BTreeMap::new();
    for &rots in &queries {
        *query_args_map.entry(rots).or_insert(0) += 1;
    }

    let nb_point_sets = query_args_map.len();

    let mut commitment_map: Vec<Vec<usize>> = Vec::new();
    for (key, value) in query_args_map {
        commitment_map.push(vec![key.count(); value]);
    }

    let gate_ops = fold_args(&gate_args);
    let lookup_ops = fold_args(&lookup_args);
    let trash_ops = fold_args(&trashcan_args);

    // Proof and VK sizes at pi=1, ci=0 (minimal baseline for this chip in isolation).
    let proof_size = estimate_proof_size::<PCS>(
        0,
        nb_advice,
        nb_lookups,
        nb_trashcans,
        circuit_degree,
        nb_copy_constrained,
        nb_evaluations,
        nb_point_sets,
    );
    let vk_size = estimate_vk_size::<PCS>(nb_copy_constrained, nb_fixed);
    let nb_lookup_tables = tables.len();

    ChipProfile {
        deps: deps.iter().map(|c| c.to_string()).collect::<Vec<String>>(),
        advice_cols: nb_advice,
        fixed_cols: nb_fixed,
        copy_constraints: nb_copy_constrained,
        nb_lookup_tables,
        lookups: nb_lookups,
        trash: nb_trashcans,
        degree: circuit_degree,
        evals: nb_evaluations,
        gates: nb_gates,
        gate_ops,
        lookup_ops,
        trash_ops,
        commitment_map,
        proof_size,
        vk_size,
    }
}
