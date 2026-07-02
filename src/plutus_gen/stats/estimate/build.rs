use super::super::arguments::permutation::{PERM_DEGREE, permutation_query_rotations};
use super::super::arguments::trashcans::TRASH_DEGREE;
use super::super::arguments::vanishing::vanishing_query_rotations;
use super::super::data::CircuitConfig;
use super::super::lookup::{LookupEstimate, PlookUp};
use super::super::pcs::PcsEstimate;
use crate::plutus_gen::stats::chips::{
    Argument, Column, RotationSet, ScalarExpression, SupportedChips, flatten_chips, flatten_tables,
    merge_chips_advice, merge_chips_fixed,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Processed {
    pub(crate) circuit_degree: usize,
    pub(crate) nb_public_inputs: usize,
    pub(crate) nb_committed_instances: usize,
    pub(crate) nb_advice: usize,
    pub(crate) nb_fixed: usize,
    pub(crate) nb_copy_constrained: usize,
    pub(crate) gate_args: Vec<Argument>,
    pub(crate) lookup_args: Vec<Argument>,
    pub(crate) trashcan_args: Vec<Argument>,
    pub(crate) nb_advice_fixed_evaluations: usize,
    pub(crate) max_advice_queries: usize,
    pub(crate) commitment_map: Vec<Vec<usize>>,
    pub(crate) kzg_halo2_point_sets: Vec<usize>,
    pub(crate) nb_point_sets: usize,
    pub(crate) max_commitments_per_query: usize,
    pub(crate) recursion: bool,
}

pub(crate) fn compute_degree(
    extra_degree: usize,
    nb_copy_constrained: usize,
    nb_lookup_args: usize,
    nb_trash_args: usize,
    chips: &std::collections::BTreeSet<SupportedChips>,
) -> usize {
    [extra_degree]
        .into_iter()
        .chain(nb_copy_constrained.gt(&0).then_some(PERM_DEGREE))
        .chain(nb_lookup_args.gt(&0).then_some(PlookUp::lookup_degree()))
        .chain(nb_trash_args.gt(&0).then_some(TRASH_DEGREE))
        .chain(chips.iter().map(|c| c.degree()))
        .max()
        .unwrap_or(0)
}

/// Estimates verifier operation counts from chip descriptions and optional extra column counts.
///
/// `extra.nb_advice`, `extra.nb_fixed + extra.nb_selectors`, and `extra.nb_lookups` are summed
/// with chip-derived values. `circuit_degree` is the max of `extra.degree` and the chips'
/// degrees. All counts are lower bounds: they assume the minimal rotation set {prev, cur, next}.
pub(crate) fn process<PCS>(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> Processed
where
    PCS: PcsEstimate,
{
    let extra_nb_evaluations = if extra.nb_evaluations > 0 {
        // All advice columns are assumed to be copy constrained, and so evaluated on `current`
        assert!(extra.nb_evaluations >= extra.nb_advice);
        // We assume that some of the advice and fixed wires are queried on `current` and `next`
        assert!(extra.nb_evaluations <= 2 * (extra.nb_advice + extra.nb_fixed));
        extra.nb_evaluations
    } else {
        // we assume that all advice are queried on `current`
        extra.nb_advice
    };

    debug_assert!(
        !used_chips
            .iter()
            .any(|c| matches!(c, SupportedChips::P2RDecomposition(_))),
        "P2RDecomposition must not be in used_chips — it is resolved from nr_pow2range_cols"
    );
    debug_assert!(
        !used_chips
            .iter()
            .any(|c| matches!(c, SupportedChips::VerifierGadget)),
        "VerifierGadget must not be in used_chips — it is resolved from recursion boolean"
    );

    // We make sure to have a single P2RDecomposition chip by adding it manually
    let mut all_chips = used_chips.to_vec();
    if recursion {
        all_chips.push(SupportedChips::VerifierGadget);
    }

    let p2r_n = extra.nr_pow2range_cols.unwrap_or_else(|| {
        flatten_chips(&all_chips)
            .iter()
            .map(|c| c.nr_pow2range_cols())
            .max()
            .unwrap_or(0)
    });
    if p2r_n > 0 {
        all_chips.push(SupportedChips::P2RDecomposition(p2r_n));
    }
    let effective_chips = flatten_chips(&all_chips);
    let effective_tables = flatten_tables(&all_chips);

    // Updating advice columns.
    let advice_columns = {
        // Merging all advice columns
        let merged = merge_chips_advice(&effective_chips);

        // Creating extras columns
        let mut extras = Vec::new();
        (0..extra.nb_advice).for_each(|i| {
            let rotations = if i + extra.nb_advice + extra.nb_fixed < extra_nb_evaluations {
                RotationSet::new(false, false, true, true, false)
            } else {
                RotationSet::curr()
            };
            let col = Column::advice(rotations, true);
            extras.push(col);
        });
        [merged, extras].concat()
    };
    let advice_queries = advice_columns
        .iter()
        .map(|c| c.rotations())
        .collect::<Vec<RotationSet>>();
    let nb_advice = advice_columns.len();
    let max_advice_queries = advice_queries
        .iter()
        .map(|queries| queries.count())
        .max()
        .unwrap_or(1);

    // Updating fixed columns.
    let fixed_columns = {
        // Merging all shared fixed and exclusive_fixed columns
        let merged = merge_chips_fixed(&effective_chips);

        // Creating table columns
        let mut tables = Vec::new();
        for table in effective_tables {
            (0..table.nb_columns).for_each(|_| {
                // In theory, table column could be called on any rotation but in practice only current rotation
                let col = Column::table(RotationSet::curr());
                tables.push(col);
            });
        }

        // Creating extras columns
        let mut extras_fixed = Vec::new();
        (0..extra.nb_fixed).for_each(|i| {
            let rotations = if i + 2 * extra.nb_advice + extra.nb_fixed < extra_nb_evaluations {
                RotationSet::new(false, false, true, true, false)
            } else {
                RotationSet::curr()
            };
            // We assume that the extra columns are _NOT_ copy constrained
            let col = Column::exclusive_fixed(rotations, false);
            extras_fixed.push(col);
        });

        // Creating extras selectors
        let mut extras_selectors = Vec::new();
        (0..extra.nb_selectors).for_each(|_| {
            // We assume that the extra selectors are queried only on the current rotation
            let col = Column::selector();
            extras_selectors.push(col);
        });

        [merged, tables, extras_fixed, extras_selectors].concat()
    };
    let fixed_queries = fixed_columns
        .iter()
        .map(|c| c.rotations())
        .collect::<Vec<RotationSet>>();
    let nb_fixed = fixed_columns.len();

    // Number of copy-contrained columns.
    // We assume all new advice wires are copy constrained, and no new fixed wires are.
    let nb_copy_constrained = (nb_public_inputs > 0) as usize
        + (nb_committed_instances > 0) as usize
        + advice_columns
            .iter()
            .map(|c| c.is_copy_constrained() as usize)
            .sum::<usize>()
        + fixed_columns
            .iter()
            .map(|c| c.is_copy_constrained() as usize)
            .sum::<usize>();

    // Summing number of advice and fixed queries.
    let nb_advice_queries = advice_queries.iter().fold(0, |acc, q| acc + q.count());
    let nb_fixed_queries = fixed_queries.iter().fold(0, |acc, q| acc + q.count());
    let nb_advice_fixed_evaluations = nb_advice_queries + nb_fixed_queries;

    // Number of lookup arguments (each contributing Z_lookup, A_permuted, S_permuted).
    // We suppose we have one lookup argument with extra.nb_lookups constraints.
    let nb_lookup_args = (extra.nb_lookups > 0) as usize
        + effective_chips
            .iter()
            .map(|c| c.nb_lookup_args())
            .sum::<usize>();

    // Number of trashcan arguments.
    let nb_trash_args: usize = effective_chips.iter().map(|c| c.nb_trashcan_args()).sum();

    // Circuit degree.
    let circuit_degree = compute_degree(
        extra.degree,
        nb_copy_constrained,
        nb_lookup_args,
        nb_trash_args,
        &effective_chips,
    );

    // Creating committed instances queries
    let mut committed_queries = Vec::new();
    if nb_committed_instances > 0 {
        committed_queries.push(RotationSet::curr());
    }

    // Creating permutation queries
    let permutation_queries = permutation_query_rotations(nb_copy_constrained, circuit_degree);

    // Creating vanishing queries
    let vanishing_queries = vanishing_query_rotations();

    // Creating lookup queries
    let mut lookup_queries = Vec::new();
    (0..nb_lookup_args).for_each(|_| {
        lookup_queries.extend(PlookUp::lookup_poly_rotations());
    });

    // Creating trashcan queries
    let mut trashcan_queries = BTreeSet::new();
    (0..nb_trash_args).for_each(|_| {
        trashcan_queries.insert(RotationSet::curr());
    });

    let queries = advice_queries
        .into_iter()
        .chain(fixed_queries)
        .chain(committed_queries)
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

    let max_commitments_per_query = query_args_map
        .iter()
        .map(|(_query_key, &nb_args)| nb_args)
        .max()
        .unwrap_or(1);

    let kzg_halo2_point_sets = query_args_map
        .keys()
        .map(|query| query.count())
        .collect::<Vec<usize>>();

    let mut commitment_map: Vec<Vec<usize>> = Vec::new();
    for (key, value) in query_args_map {
        commitment_map.push(vec![key.count(); value]);
    }

    // Computing operations per gate
    let gate_expressions = effective_chips.iter().flat_map(|c| c.gates()).collect();

    // Computing Lookup evals
    let mut input_lookup_expression_ops = effective_chips
        .iter()
        .flat_map(|c| c.lookups())
        .collect::<Vec<Vec<ScalarExpression>>>();

    // Adding a single argument of extra.nb_lookups
    if extra.nb_lookups > 0 {
        let extra_lookup_exp_ops = (0..extra.nb_lookups)
            .map(|_| ScalarExpression::lookup_expression(0, 0, 0, 0, 0, 1, 0))
            .collect::<Vec<ScalarExpression>>();
        input_lookup_expression_ops.push(extra_lookup_exp_ops);
    }

    // Computing trashcans evals
    let trashcan_args = effective_chips
        .iter()
        .flat_map(|c| c.trashcans())
        .collect::<Vec<Vec<ScalarExpression>>>();

    Processed {
        circuit_degree,
        nb_public_inputs,
        nb_committed_instances,
        nb_advice,
        nb_fixed,
        nb_copy_constrained,
        gate_args: gate_expressions,
        lookup_args: input_lookup_expression_ops,
        trashcan_args,
        nb_advice_fixed_evaluations,
        max_advice_queries,
        commitment_map,
        kzg_halo2_point_sets,
        nb_point_sets,
        max_commitments_per_query,
        recursion,
    }
}
