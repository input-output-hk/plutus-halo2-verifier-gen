//! All functions related to data's name and manipulation in Plinth language

use crate::plutus_gen::extraction::data::{
    Commitments, Evaluations, ExpressionG1, ScalarExpression,
};
use midnight_curves::BlsScalar as Scalar;
use midnight_proofs::plonk::Expression;
use std::io::{BufWriter, Result, Write};

use crate::plutus_gen::extraction::languages::*;

pub trait PlinthExpression {
    fn compile_expression(&self) -> String;
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
    compiled.iter().fold(ZERO_STR.to_string(), |acc, eval| {
        format!("({} * {} + {})", acc, THETA_STR, eval)
    })
}

impl PlinthExpression for Commitments {
    fn compile_expression(&self) -> String {
        match self {
            Commitments::Advice(index) => {
                format!("a{:?}", index)
            }
            Commitments::Fixed(index) => {
                format!("f{:?}_commitment", index)
            }
            Commitments::Permutation(set) => {
                format!("permutations_committed_{}", set)
            }
            Commitments::Lookup(index) => {
                format!("lookupCommitment{:?}", index)
            }
            Commitments::PermutedInput(index) => {
                format!("permutedInput{:?}", index)
            }
            Commitments::PermutedTable(index) => {
                format!("permutedTable{:?}", index)
            }
            Commitments::PermutationsCommon(index) => {
                format!("p{:?}_commitment", index)
            }
            Commitments::VanishingG => VANISH_G_STR.to_string(),
            Commitments::VanishingRand => "vanishingRand".to_string(),
        }
    }
}

impl PlinthExpression for Evaluations {
    fn compile_expression(&self) -> String {
        match self {
            Evaluations::Advice(index) => {
                format!("adviceEval{:?}", index)
            }
            Evaluations::Fixed(index) => {
                format!("fixedEval{:?}", index)
            }
            Evaluations::Permutation(set, index) => perm_eval_str(set, *index),
            Evaluations::Lookup(index) => {
                format!("product_eval_{:?}", index)
            }
            Evaluations::LookupNext(index) => {
                format!("product_next_eval_{:?}", index)
            }
            Evaluations::PermutedInput(index) => {
                format!("permuted_input_eval_{:?}", index)
            }
            Evaluations::PermutedInputInverse(index) => {
                format!("permuted_input_inv_eval_{:?}", index)
            }
            Evaluations::PermutedTable(index) => {
                format!("permuted_table_eval_{:?}", index)
            }
            Evaluations::PermutationsCommon(index) => {
                format!("permutationCommon{:?}", index)
            }

            Evaluations::VanishingS => "vanishing_s".to_string(),

            Evaluations::RandomEval => "randomEval".to_string(),
        }
    }
}

trait PlinthTranspiler {
    fn plinth_polynomial<W: Write>(&self, writer: &mut W) -> Result<()>;
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
                scalar.plinth_polynomial(writer)?;
                writer.write_all(b" ")?;
                a.plinth_polynomial(writer)?;
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
