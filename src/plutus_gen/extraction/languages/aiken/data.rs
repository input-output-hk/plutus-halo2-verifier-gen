//! All functions related to data's name and manipulation in Aiken language

use crate::plutus_gen::extraction::data::{
    Commitments, Evaluations, ExpressionG1, ScalarExpression,
};
use midnight_curves::BlsScalar as Scalar;
use midnight_proofs::plonk::Expression;
use std::io::{BufWriter, Result, Write};

use crate::plutus_gen::extraction::languages::*;

pub trait AikenExpression {
    fn compile_expression(&self) -> String;
}

pub fn combine_aiken_expressions(lookup_expressions: Vec<Expression<Scalar>>) -> String {
    let compiled: Vec<_> = lookup_expressions
        .iter()
        .map(AikenExpression::compile_expression)
        .collect();
    compiled.iter().fold(ZERO_STR.to_string(), |acc, eval| {
        format!("add(mul({}, {}), {})", acc, THETA_STR, eval)
    })
}

impl AikenExpression for Evaluations {
    fn compile_expression(&self) -> String {
        match self {
            Evaluations::Advice(index) => {
                format!("advice_eval_{:?}", index)
            }
            Evaluations::Fixed(index) => {
                format!("fixed_eval_{:?}", index)
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
                format!("permutation_common_{:?}", index)
            }
            Evaluations::VanishingS => "vanishing_s".to_string(),
            Evaluations::RandomEval => "random_eval".to_string(),
        }
    }
}

impl AikenExpression for Commitments {
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
                format!("lookup_commitment_{:?}", index)
            }
            Commitments::PermutedInput(index) => {
                format!("permuted_input_{:?}", index)
            }
            Commitments::PermutedTable(index) => {
                format!("permuted_table_{:?}", index)
            }
            Commitments::PermutationsCommon(index) => {
                format!("p{:?}_commitment", index)
            }
            Commitments::VanishingG => VANISH_G_STR.to_string(),
            Commitments::VanishingRand => "vanishing_rand".to_string(),
        }
    }
}

trait AikenTranspiler {
    fn aiken_polynomial<W: Write>(&self, writer: &mut W) -> Result<()>;
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
