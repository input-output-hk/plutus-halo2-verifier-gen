use crate::plutus_gen::extraction::data::{ExpressionG1, ScalarExpression};
use midnight_curves::BlsScalar as Scalar;

use group::Curve;
use midnight_proofs::{
    plonk::{Advice, Any, Column, Expression, Fixed, Instance, VerifyingKey},
    poly::{Rotation, commitment::PolynomialCommitmentScheme},
};
use std::io::{BufWriter, Result, Write};

pub trait AikenExpression {
    fn compile_expression(&self) -> String;
}
pub trait PlinthExpression {
    fn compile_expression(&self) -> String;
}

trait PlinthTranspiler {
    fn plinth_polynomial<W: Write>(&self, writer: &mut W) -> Result<()>;
}
trait AikenTranspiler {
    fn aiken_polynomial<W: Write>(&self, writer: &mut W) -> Result<()>;
}

impl<E: PlinthTranspiler> PlinthExpression for E {
    fn compile_expression(&self) -> String {
        let mut buf = BufWriter::new(Vec::new());
        let _ = self.plinth_polynomial(&mut buf);
        let bytes = buf
            .into_inner()
            .expect("failed to get bytes for compiled expression");
        String::from_utf8(bytes).expect("failed to convert bytes to string")
    }
}

impl<E: AikenTranspiler> AikenExpression for E {
    fn compile_expression(&self) -> String {
        let mut buf = BufWriter::new(Vec::new());
        let _ = self.aiken_polynomial(&mut buf);
        let bytes = buf
            .into_inner()
            .expect("failed to get bytes for compiled expression");
        String::from_utf8(bytes).expect("failed to convert bytes to string")
    }
}

impl AikenTranspiler for Expression<Scalar> {
    fn aiken_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Expression::Constant(scalar) => {
                write!(writer, "from_int(0x{})", hex::encode(scalar.to_bytes_be()))
            }
            Expression::Selector(_selector) => {
                panic!("Selector not supported in custom gate")
            }
            Expression::Fixed(query) => {
                write!(
                    writer,
                    "fixed_eval_{}",
                    query.index().expect("unable to get the index of the query") + 1
                )
            }
            Expression::Advice(query) => {
                write!(
                    writer,
                    "advice_eval_{}",
                    query.index.expect("unable to get the index of the query") + 1
                )
            }
            Expression::Instance(_query) => {
                panic!("Instance not supported")
            }
            Expression::Challenge(_challenge) => {
                panic!("Challenge not supported")
            }
            Expression::Negated(a) => {
                writer.write_all(b" neg(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b") ")
            }
            Expression::Sum(a, b) => {
                writer.write_all(b"add(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                b.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            Expression::Product(a, b) => {
                writer.write_all(b"mul(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                b.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            Expression::Scaled(a, f) => {
                writer.write_all(b"mul(")?;
                a.aiken_polynomial(writer)?;
                write!(writer, ", {:?})", f)
            }
        }
    }
}

impl AikenTranspiler for ExpressionG1<Scalar> {
    fn aiken_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            ExpressionG1::Zero => writer.write_all(b" zero "),
            ExpressionG1::Sum(a, b) => {
                writer.write_all(b"addG1(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                b.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ExpressionG1::Scale(a, scalar) => {
                writer.write_all(b"scaleG1(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                scalar.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ExpressionG1::Variable(name) => {
                write!(writer, " {} ", name)
            }
            ExpressionG1::VanishingSplit(index) => {
                write!(writer, " vanishing_split_{} ", index)
            }
        }
    }
}

impl AikenTranspiler for ScalarExpression<Scalar> {
    fn aiken_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            ScalarExpression::Constant(value) => {
                write!(writer, "from_int({})", hex::encode(value.to_bytes_be()))
            }
            ScalarExpression::Variable(name) => {
                write!(writer, " {} ", name)
            }
            ScalarExpression::Negated(a) => {
                writer.write_all(b"neg(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ScalarExpression::Sum(a, b) => {
                writer.write_all(b"add(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                b.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ScalarExpression::Product(a, b) => {
                writer.write_all(b"mul(")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b", ")?;
                b.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ScalarExpression::PowMod(a, exponent) => {
                writer.write_all(b"scale(")?;
                a.aiken_polynomial(writer)?;
                write!(writer, ", {:?})", exponent)
            }
            ScalarExpression::Advice(index) => {
                write!(writer, "advice_eval_{}", index)
            }
            ScalarExpression::Fixed(index) => {
                write!(writer, "fixed_eval_{}", index)
            }
            ScalarExpression::Instance(index) => {
                write!(writer, "instance_eval_{:?}", index)
            }
            ScalarExpression::PermutationCommon(index) => {
                write!(writer, "permutation_common_{:?}", index)
            }
        }
    }
}

impl PlinthTranspiler for Expression<Scalar> {
    fn plinth_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
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
                write!(
                    writer,
                    "fixedEval{}",
                    query.index().expect("unable to get the index of the query") + 1
                )
            }
            Expression::Advice(query) => {
                write!(
                    writer,
                    "adviceEval{}",
                    query.index.expect("unable to get the index of the query") + 1
                )
            }
            Expression::Instance(_query) => {
                panic!("Instance not supported")
            }
            Expression::Challenge(_challenge) => {
                panic!("Challenge not supported")
            }
            Expression::Negated(a) => {
                writer.write_all(b"( negate ")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" )")
            }
            Expression::Sum(a, b) => {
                writer.write_all(b"(")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" + ")?;
                b.plinth_polynomial(writer)?;
                writer.write_all(b")")
            }
            Expression::Product(a, b) => {
                writer.write_all(b"(")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" * ")?;
                b.plinth_polynomial(writer)?;
                writer.write_all(b")")
            }
            Expression::Scaled(a, f) => {
                a.plinth_polynomial(writer)?;
                write!(writer, " * {:?}", f)
            }
        }
    }
}
impl PlinthTranspiler for ExpressionG1<Scalar> {
    fn plinth_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            ExpressionG1::Zero => {
                writer.write_all(b" (bls12_381_G1_uncompress bls12_381_G1_compressed_zero) ")
            }
            ExpressionG1::Sum(a, b) => {
                writer.write_all(b"( ")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" + ")?;
                b.plinth_polynomial(writer)?;
                writer.write_all(b")")
            }
            ExpressionG1::Scale(a, scalar) => {
                writer.write_all(b"(scale ")?;
                scalar.aiken_polynomial(writer)?;
                writer.write_all(b" ")?;
                a.aiken_polynomial(writer)?;
                writer.write_all(b")")
            }
            ExpressionG1::Variable(name) => {
                write!(writer, " {} ", name)
            }
            ExpressionG1::VanishingSplit(index) => {
                write!(writer, " vanishingSplit_{} ", index)
            }
        }
    }
}

impl PlinthTranspiler for ScalarExpression<Scalar> {
    fn plinth_polynomial<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            ScalarExpression::Constant(value) => {
                write!(
                    writer,
                    "(mkScalar (0x{} `modulo` bls12_381_field_prime))",
                    hex::encode(value.to_bytes_be())
                )
            }
            ScalarExpression::Variable(name) => {
                write!(writer, " {} ", name)
            }
            ScalarExpression::Negated(a) => {
                writer.write_all(b"( negate ")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" )")
            }
            ScalarExpression::Sum(a, b) => {
                writer.write_all(b"(")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" + ")?;
                b.plinth_polynomial(writer)?;
                writer.write_all(b")")
            }
            ScalarExpression::Product(a, b) => {
                writer.write_all(b"(")?;
                a.plinth_polynomial(writer)?;
                writer.write_all(b" * ")?;
                b.plinth_polynomial(writer)?;
                writer.write_all(b")")
            }
            ScalarExpression::PowMod(a, exponent) => {
                writer.write_all(b"( powMod ")?;
                a.plinth_polynomial(writer)?;
                write!(writer, " {} ", exponent)?;
                writer.write_all(b" )")
            }
            ScalarExpression::Advice(index) => {
                write!(writer, "adviceEval{:?}", index)
            }
            ScalarExpression::Fixed(index) => {
                write!(writer, "fixedEval{:?}", index)
            }
            ScalarExpression::Instance(index) => {
                write!(writer, "instanceEval{:?}", index)
            }
            ScalarExpression::PermutationCommon(index) => {
                write!(writer, "permutationCommon{:?}", index)
            }
        }
    }
}

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

// fold expressions for particular lookup
// initial ACC = ZERO
// folding : ACC = (acc * theta + eval)
// where eval is subsequent expressions
// separate for input and for table expression
pub fn combine_plinth_expressions(lookup_expressions: Vec<Expression<Scalar>>) -> String {
    let compiled: Vec<_> = lookup_expressions
        .iter()
        .map(PlinthExpression::compile_expression)
        .collect();
    compiled.iter().fold("scalarZero".to_string(), |acc, eval| {
        format!("({} * theta + {})", acc, eval)
    })
}

pub fn combine_aiken_expressions(lookup_expressions: Vec<Expression<Scalar>>) -> String {
    let compiled: Vec<_> = lookup_expressions
        .iter()
        .map(AikenExpression::compile_expression)
        .collect();
    compiled.iter().fold("scalarZero".to_string(), |acc, eval| {
        format!("add(mul({}, theta), {})", acc, eval)
    })
}
