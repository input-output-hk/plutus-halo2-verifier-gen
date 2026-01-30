use super::super::{ScalarExpression, constants::*};

use midnight_curves::{BlsScalar as Scalar, G1Projective};
use midnight_proofs::plonk::{Advice, Any, Column, Error, Fixed, Instance, VerifyingKey};
use midnight_proofs::poly::{Rotation, commitment::PolynomialCommitmentScheme};

use anyhow::Ok;
use group::Curve;

type Terms = Vec<(char, ScalarExpression<Scalar>)>;

fn get_any_query_index<S>(vk: &VerifyingKey<Scalar, S>, column: Column<Any>, at: Rotation) -> usize
where
    S: PolynomialCommitmentScheme<Scalar>,
    S::Commitment: Curve,
{
    match column.column_type() {
        Any::Advice(_) => {
            for (index, advice_query) in vk.cs().advice_queries().iter().enumerate() {
                if advice_query
                    == &(
                        Column::<Advice>::try_from(column).unwrap_or_else(|err| {
                            panic!(
                                "expected Advice column but got {:?} with error {}",
                                column, err
                            )
                        }),
                        at,
                    )
                {
                    return index;
                }
            }
            panic!("get_advice_query_index called for non-existent query");
        }
        Any::Fixed => {
            for (index, advice_query) in vk.cs().fixed_queries().iter().enumerate() {
                if advice_query
                    == &(
                        Column::<Fixed>::try_from(column).unwrap_or_else(|err| {
                            panic!(
                                "expected Fixed column but got {:?} with error {}",
                                column, err
                            )
                        }),
                        at,
                    )
                {
                    return index;
                }
            }
            panic!("get_fixed_query_index called for non-existent query");
        }
        Any::Instance => {
            for (index, advice_query) in vk.cs().instance_queries().iter().enumerate() {
                if advice_query
                    == &(
                        Column::<Instance>::try_from(column).unwrap_or_else(|err| {
                            panic!(
                                "expected Instance column but got {:?} with error {}",
                                column, err
                            )
                        }),
                        at,
                    )
                {
                    return index;
                }
            }
            panic!("get_instance_query_index called for non-existent query");
        }
    }
}

pub fn evaluate_permutations_terms(
    sets: &Vec<char>,
) -> Result<Vec<ScalarExpression<Scalar>>, anyhow::Error> {
    // TODO think about errors returned
    let first_set = sets
        .first()
        .ok_or("unable to get first element of the set")
        .map_err(|e| Error::Synthesis(e.to_string()))?;
    let last_set = sets
        .last()
        .ok_or("unable to get last element of the set")
        .map_err(|e| Error::Synthesis(e.to_string()))?;
    let shifted_sets: Vec<_> = sets.iter().skip(1).zip(sets.iter()).collect();

    let mut terms: Vec<ScalarExpression<Scalar>> = Vec::new();
    //evaluation_at_0 * (scalarOne - permutations_evaluated_{}_1)
    //a * (b - c)
    let a = ScalarExpression::Variable(EVAL_0_STR.to_string());
    let b = ScalarExpression::Variable(ONE_STR.to_string());
    let c = ScalarExpression::Variable(perm_eval_str(first_set, 1));

    let term = ScalarExpression::Product(
        Box::new(a),
        Box::new(ScalarExpression::Sum(
            Box::new(b),
            Box::new(ScalarExpression::Negated(Box::new(c))),
        )),
    );

    terms.push(term);

    //last_evaluation * (permutations_evaluated_{}_1 * permutations_evaluated_{}_1 - permutations_evaluated_{}_1)
    //a * (b * b - b)
    let a = ScalarExpression::Variable(EVAL_LAST_STR.to_string());
    let b = ScalarExpression::Variable(perm_eval_str(last_set, 1));

    let term = ScalarExpression::Product(
        Box::new(a),
        Box::new(ScalarExpression::Sum(
            Box::new(ScalarExpression::Product(
                Box::new(b.clone()),
                Box::new(b.clone()),
            )),
            Box::new(ScalarExpression::Negated(Box::new(b))),
        )),
    );

    terms.push(term);

    for (next, current) in shifted_sets {
        // (permutations_evaluated_{}_1 - permutations_evaluated_{}_3) * evaluation_at_0
        // (a - b) * c

        let a = ScalarExpression::Variable(perm_eval_str(next, 1));
        let neg_b = ScalarExpression::Negated(Box::new(ScalarExpression::Variable(perm_eval_str(
            current, 3,
        ))));
        let c = ScalarExpression::Variable(EVAL_0_STR.to_string());

        let term = ScalarExpression::Product(
            Box::new(ScalarExpression::Sum(Box::new(a), Box::new(neg_b))),
            Box::new(c),
        );

        terms.push(term);
    }

    Ok(terms)
}

pub fn permutation_terms_both<S>(
    vk: &VerifyingKey<Scalar, S>,
    chunk_len: usize,
    sets: &Vec<char>,
    nb_permutation_common: usize,
) -> Result<(Terms, Terms), anyhow::Error>
where
    S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let mut terms_left: Vec<(char, ScalarExpression<_>)> = Vec::new();
    let mut terms_right: Vec<(char, ScalarExpression<_>)> = Vec::new();

    sets.iter()
        .zip(vk.cs().permutation().columns.chunks(chunk_len))
        // replace with proof extractions permutations_common
        .zip(1..=nb_permutation_common)
        .enumerate()
        .for_each(|(chunk_index, ((set, columns), _))| {
            columns.iter().enumerate().for_each(|(idx, &column)| {
                let permutation_index = (chunk_index * chunk_len) + idx + 1;
                let eval_index = get_any_query_index(vk, column, Rotation::cur()) + 1;
                match column.column_type() {
                    Any::Advice(_) => {
                        // (adviceEval{:?} + (beta * permutationCommon{:?}) + gamma)
                        // a + (b * c) + d
                        let a = ScalarExpression::Advice(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::PermutationCommon(permutation_index);
                        let d = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                            )),
                            Box::new(d),
                        );

                        terms_left.push((*set, term));
                    }
                    Any::Fixed => {
                        // (fixedEval{:?} + (beta * permutationCommon{:?}) + gamma)
                        // a + (b * c) + d
                        let a = ScalarExpression::Fixed(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::PermutationCommon(permutation_index);
                        let d = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                            )),
                            Box::new(d),
                        );

                        terms_left.push((*set, term));
                    }
                    Any::Instance => {
                        // (instanceEval{:?} + (beta * permutationCommon{:?}) + gamma)
                        // a + (b * c) + d
                        let a = ScalarExpression::Instance(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::PermutationCommon(permutation_index);
                        let d = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                            )),
                            Box::new(d),
                        );

                        #[cfg(feature = "plutus_debug")]
                        info!("- instance: {:?}", term);

                        terms_left.push((*set, term));
                    }
                }
            });

            columns.iter().enumerate().for_each(|(idx, &column)| {
                let power = chunk_index * chunk_len + idx;
                let eval_index = get_any_query_index(vk, column, Rotation::cur()) + 1;
                match column.column_type() {
                    Any::Advice(_) => {
                        // (adviceEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)
                        // a + (b * c) * d + e

                        let a = ScalarExpression::Advice(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::Variable(X_STR.to_string());
                        let d = ScalarExpression::PowMod(
                            Box::new(ScalarExpression::Variable(SCALAR_DELTA_STR.to_string())),
                            power,
                        );
                        let e = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(
                                    Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                                    Box::new(d),
                                )),
                            )),
                            Box::new(e),
                        );

                        terms_right.push((*set, term));
                    }
                    Any::Fixed => {
                        // (fixedEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)
                        // a + (b * c) * d + e

                        let a = ScalarExpression::Fixed(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::Variable(X_STR.to_string());
                        let d = ScalarExpression::PowMod(
                            Box::new(ScalarExpression::Variable(SCALAR_DELTA_STR.to_string())),
                            power,
                        );
                        let e = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(
                                    Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                                    Box::new(d),
                                )),
                            )),
                            Box::new(e),
                        );

                        terms_right.push((*set, term));
                    }
                    Any::Instance => {
                        // (instanceEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)
                        // a + (b * c) * d + e

                        let a = ScalarExpression::Instance(eval_index);
                        let b = ScalarExpression::Variable(BETA_STR.to_string());
                        let c = ScalarExpression::Variable(X_STR.to_string());
                        let d = ScalarExpression::PowMod(
                            Box::new(ScalarExpression::Variable(SCALAR_DELTA_STR.to_string())),
                            power,
                        );
                        let e = ScalarExpression::Variable(GAMMA_STR.to_string());

                        let term = ScalarExpression::Sum(
                            Box::new(ScalarExpression::Sum(
                                Box::new(a),
                                Box::new(ScalarExpression::Product(
                                    Box::new(ScalarExpression::Product(Box::new(b), Box::new(c))),
                                    Box::new(d),
                                )),
                            )),
                            Box::new(e),
                        );

                        terms_right.push((*set, term));
                    }
                }
            });
        });
    Ok((terms_left, terms_right))
}
