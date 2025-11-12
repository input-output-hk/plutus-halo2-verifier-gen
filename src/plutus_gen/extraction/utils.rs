use blstrs::Scalar;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::plonk::{Advice, Any, Column, Expression, Fixed, Instance, VerifyingKey};
use halo2_proofs::poly::Rotation;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use std::io::BufWriter;

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

fn convert_to_plinth_polynomial<W: std::io::Write>(
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
            convert_to_plinth_polynomial(a, writer)?;
            writer.write_all(b" )")
        }
        Expression::Sum(a, b) => {
            writer.write_all(b"(")?;
            convert_to_plinth_polynomial(a, writer)?;
            writer.write_all(b" + ")?;
            convert_to_plinth_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Product(a, b) => {
            writer.write_all(b"(")?;
            convert_to_plinth_polynomial(a, writer)?;
            writer.write_all(b" * ")?;
            convert_to_plinth_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Scaled(a, f) => {
            convert_to_plinth_polynomial(a, writer)?;
            write!(writer, " * {:?}", f)
        }
    }
}

fn convert_to_aiken_polynomial<W: std::io::Write>(
    ex: &Expression<Scalar>,
    writer: &mut W,
) -> std::io::Result<()> {
    match ex {
        Expression::Constant(scalar) => {
            write!(writer, "from_int(0x{})", hex::encode(scalar.to_bytes_be()))
        }
        Expression::Selector(_selector) => {
            panic!("Selector not supported in custom gate")
        }
        Expression::Fixed(query) => {
            write!(writer, "fixed_eval_{}", query.index().unwrap() + 1)
        }
        Expression::Advice(query) => {
            write!(writer, "advice_eval_{}", query.index.unwrap() + 1)
        }
        Expression::Instance(_query) => {
            panic!("Instance not supported")
        }
        Expression::Challenge(_challenge) => {
            panic!("Challenge not supported")
        }
        Expression::Negated(a) => {
            writer.write_all(b" neg(")?;
            convert_to_aiken_polynomial(a, writer)?;
            writer.write_all(b") ")
        }
        Expression::Sum(a, b) => {
            writer.write_all(b"add(")?;
            convert_to_aiken_polynomial(a, writer)?;
            writer.write_all(b", ")?;
            convert_to_aiken_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Product(a, b) => {
            writer.write_all(b"mul(")?;
            convert_to_aiken_polynomial(a, writer)?;
            writer.write_all(b", ")?;
            convert_to_aiken_polynomial(b, writer)?;
            writer.write_all(b")")
        }
        Expression::Scaled(a, f) => {
            writer.write_all(b"mul(")?;
            convert_to_aiken_polynomial(a, writer)?;
            write!(writer, ", {:?}", f)
        }
    }
}

// fold expressions for particular lookup
// initial ACC = ZERO
// folding : ACC = (acc * theta + eval)
// where eval is subsequent expressions
// separate for input and for table expression
pub fn collapse_plinth_expressions(lookup_expressions: Vec<Expression<Scalar>>) -> String {
    let compiled: Vec<_> = lookup_expressions
        .iter()
        .map(compile_plinth_expressions)
        .collect();
    compiled.iter().fold("scalarZero".to_string(), |acc, eval| {
        format!("({} * theta + {})", acc, eval)
    })
}

pub fn compile_plinth_expressions(expression: &Expression<Scalar>) -> String {
    let mut buf = BufWriter::new(Vec::new());
    let _ = convert_to_plinth_polynomial(expression, &mut buf);
    let bytes = buf.into_inner().unwrap();
    String::from_utf8(bytes).unwrap()
}

pub fn collapse_aiken_expressions(lookup_expressions: Vec<Expression<Scalar>>) -> String {
    let compiled: Vec<_> = lookup_expressions
        .iter()
        .map(compile_aiken_expressions)
        .collect();
    compiled.iter().fold("scalarZero".to_string(), |acc, eval| {
        format!("add(mul({}, theta), {})", acc, eval)
    })
}
pub fn compile_aiken_expressions(expression: &Expression<Scalar>) -> String {
    let mut buf = BufWriter::new(Vec::new());
    let _ = convert_to_aiken_polynomial(expression, &mut buf);
    let bytes = buf.into_inner().unwrap();
    String::from_utf8(bytes).unwrap()
}
