use crate::plutus_gen::extraction::KZGScheme;
use blstrs::Scalar;
use halo2_proofs::plonk::{Advice, Any, Column, Expression, Fixed, Instance, VerifyingKey};
use halo2_proofs::poly::Rotation;
use std::io::BufWriter;

pub fn get_any_query_index(
    vk: &VerifyingKey<Scalar, KZGScheme>,
    column: Column<Any>,
    at: Rotation,
) -> usize {
    match column.column_type() {
        Any::Advice(_) => {
            for (index, advice_query) in vk.cs().advice_queries().iter().enumerate() {
                if advice_query == &(Column::<Advice>::try_from(column).unwrap(), at) {
                    return index;
                }
            }
            panic!("get_advice_query_index called for non-existent query");
        }
        Any::Fixed => {
            for (index, advice_query) in vk.cs().fixed_queries().iter().enumerate() {
                if advice_query == &(Column::<Fixed>::try_from(column).unwrap(), at) {
                    return index;
                }
            }
            panic!("get_fixed_query_index called for non-existent query");
        }
        Any::Instance => {
            for (index, advice_query) in vk.cs().instance_queries().iter().enumerate() {
                if advice_query == &(Column::<Instance>::try_from(column).unwrap(), at) {
                    return index;
                }
            }
            panic!("get_instance_query_index called for non-existent query");
        }
    }
}

fn convert_polynomial<W: std::io::Write>(
    ex: &Expression<Scalar>,
    writer: &mut W,
) -> std::io::Result<()> {
    match ex {
        Expression::Constant(scalar) => {
            write!(
                writer,
                "(mkScalar (0x{} `modulo` bls12_381_field_prime))",
                hex::encode(scalar.to_bytes_be())
            )
        }
        Expression::Selector(_selector) => {
            panic!("Selector not supported in custom gate")
        }
        Expression::Fixed(query) => {
            write!(writer, "fixedEval{}", query.index().unwrap() + 1)
        }
        Expression::Advice(query) => {
            write!(writer, "adviceEval{}", query.index.unwrap() + 1)
        }
        Expression::Instance(_query) => {
            panic!("Instance not supported")
        }
        Expression::Challenge(_challenge) => {
            panic!("Challenge not supported")
        }
        Expression::Negated(a) => {
            writer.write_all(b"( negate ")?;
            convert_polynomial(a, writer)?;
            writer.write_all(b" )")
        }
        Expression::Sum(a, b) => {
            writer.write_all(b"(")?;
            convert_polynomial(a, writer)?;
            writer.write_all(b" + ")?;
            convert_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Product(a, b) => {
            writer.write_all(b"(")?;
            convert_polynomial(a, writer)?;
            writer.write_all(b" * ")?;
            convert_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Scaled(a, f) => {
            convert_polynomial(a, writer)?;
            write!(writer, " * {:?}", f)
        }
    }
}

pub fn compile_expressions(e: &Expression<Scalar>) -> String {
    let mut buf = BufWriter::new(Vec::new());
    let _ = convert_polynomial(e, &mut buf);
    let bytes = buf.into_inner().unwrap();
    String::from_utf8(bytes).unwrap()
}
