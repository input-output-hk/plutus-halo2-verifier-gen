use midnight_curves::BlsScalar as Scalar;

use group::Curve;
use midnight_proofs::{
    plonk::{Advice, Any, Column, Fixed, Instance, VerifyingKey},
    poly::{Rotation, commitment::PolynomialCommitmentScheme},
};

pub fn get_any_query_index<S>(
    vk: &VerifyingKey<Scalar, S>,
    column: Column<Any>,
    at: Rotation,
) -> usize
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
