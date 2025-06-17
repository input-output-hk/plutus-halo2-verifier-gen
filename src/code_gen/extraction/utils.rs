use blake2b_simd::State;
use blstrs::Scalar;
use halo2_proofs::plonk::Expression;
use halo2_proofs::transcript::{CircuitTranscript, Transcript};

pub fn read_n_scalars(
    transcript: &mut CircuitTranscript<State>,
    n: usize,
) -> Result<Vec<Scalar>, std::io::Error> {
    (0..n).map(|_| transcript.read()).collect()
}

pub fn convert_polynomial<W: std::io::Write>(
    ex: &Expression<Scalar>,
    writer: &mut W,
) -> std::io::Result<()> {
    match ex {
        Expression::Constant(scalar) => write!(
            writer,
            "(mkScalar ({:?} `modulo` bls12_381_field_prime))",
            scalar
        ),
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
