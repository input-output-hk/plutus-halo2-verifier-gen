use blstrs::Scalar;
use halo2_proofs::plonk::Expression;

use crate::plutus_gen::extraction::data::{
    ElementMSM, ExpressionG1, OptimizedMSM, ScalarExpression, ScalarOperation,
};

#[derive(Clone, Debug)]
pub struct CircuitStatistics {
    pub(crate) transcript_size: i32,
    pub(crate) public_inputs: usize,
    pub(crate) proof_size: usize,
    pub(crate) vk_size: usize,
    pub(crate) hash: Vec<usize>,
    pub(crate) neg_scalar: usize,
    pub(crate) add_scalar: usize,
    pub(crate) sub_scalar: usize,
    pub(crate) mul_scalar: usize,
    pub(crate) inv_scalar: usize,
    pub(crate) pow_scalar: usize,
    pub(crate) to_bytes_scalar: usize,
    pub(crate) from_bytes_scalar: usize,
    pub(crate) from_int_scalar: usize,
    pub(crate) add_point: usize,
    pub(crate) mul_point: usize,
    pub(crate) from_bytes_point: usize,
    pub(crate) decompress_point: usize,
    pub(crate) compress_point: usize,
    pub(crate) miller_loop: usize,
    pub(crate) pairing: usize,
}

impl CircuitStatistics {
    pub(crate) fn new(proof_size: usize, vk_size: usize, public_inputs: usize) -> Self {
        CircuitStatistics {
            transcript_size: proof_size as i32,
            public_inputs,
            proof_size,
            vk_size,
            hash: Vec::<usize>::new(),
            neg_scalar: 0,
            add_scalar: 0,
            sub_scalar: 0,
            mul_scalar: 0,
            inv_scalar: 0,
            pow_scalar: 0,
            from_int_scalar: 0,
            to_bytes_scalar: 0,
            from_bytes_scalar: 0,
            add_point: 0,
            mul_point: 0,
            from_bytes_point: 0,
            decompress_point: 0,
            compress_point: 0,
            miller_loop: 2,
            pairing: 1,
        }
    }

    pub(crate) fn difference(stat1: &Self, stat2: &Self) -> Self {
        CircuitStatistics {
            transcript_size: stat1.transcript_size - stat2.transcript_size,
            public_inputs: stat1.public_inputs.abs_diff(stat2.public_inputs),
            proof_size: stat1.proof_size.abs_diff(stat2.proof_size),
            vk_size: stat1.vk_size.abs_diff(stat2.vk_size),
            hash: {
                let max_len = stat1.hash.len().max(stat2.hash.len());
                (0..max_len)
                    .map(|i| {
                        let a = stat1.hash.get(i).cloned().unwrap_or(0);
                        let b = stat2.hash.get(i).cloned().unwrap_or(0);
                        a.abs_diff(b)
                    })
                    .collect()
            },
            neg_scalar: stat1.neg_scalar.abs_diff(stat2.neg_scalar),
            add_scalar: stat1.add_scalar.abs_diff(stat2.add_scalar),
            sub_scalar: stat1.sub_scalar.abs_diff(stat2.sub_scalar),
            mul_scalar: stat1.mul_scalar.abs_diff(stat2.mul_scalar),
            inv_scalar: stat1.inv_scalar.abs_diff(stat2.inv_scalar),
            pow_scalar: stat1.pow_scalar.abs_diff(stat2.pow_scalar),
            to_bytes_scalar: stat1.to_bytes_scalar.abs_diff(stat2.to_bytes_scalar),
            from_bytes_scalar: stat1.from_bytes_scalar.abs_diff(stat2.from_bytes_scalar),
            from_int_scalar: stat1.from_int_scalar.abs_diff(stat2.from_int_scalar),
            add_point: stat1.add_point.abs_diff(stat2.add_point),
            mul_point: stat1.mul_point.abs_diff(stat2.mul_point),
            from_bytes_point: stat1.from_bytes_point.abs_diff(stat2.from_bytes_point),
            decompress_point: stat1.decompress_point.abs_diff(stat2.decompress_point),
            compress_point: stat1.compress_point.abs_diff(stat2.compress_point),
            miller_loop: stat1.miller_loop.abs_diff(stat2.miller_loop),
            pairing: stat1.pairing.abs_diff(stat2.pairing),
        }
    }

    pub(crate) fn msm_operation(&mut self, msm: &OptimizedMSM) {
        msm.elements.iter().for_each(|element| {
            // Evaluating the scalars
            match element {
                ElementMSM::Element(scalar, _commitment) => self.scalar_operation(scalar),
                ElementMSM::ElementNegatedG1(scalar) => self.scalar_operation(scalar),
                ElementMSM::ElementW(scalar, _index) => self.scalar_operation(scalar),
            };

            // Evaluating the MSM by folding
            self.decompress_point();
            self.scale();
            self.add_point();
        });
    }

    pub(crate) fn scalar_operation(&mut self, operation: &ScalarOperation) {
        match operation {
            ScalarOperation::Mul(scalar, _evaluation)
                if matches!(**scalar, ScalarOperation::Power(_, 0)) =>
            {
                ()
            }
            ScalarOperation::MulS(scalar_a, scalar_b)
                if matches!(**scalar_a, ScalarOperation::Power(_, 0)) =>
            {
                self.scalar_operation(scalar_b)
            }
            ScalarOperation::MulS(scalar_a, scalar_b)
                if matches!(**scalar_b, ScalarOperation::Power(_, 0)) =>
            {
                self.scalar_operation(scalar_a)
            }
            ScalarOperation::Power(_name, exponent) if *exponent == 0 => (),
            ScalarOperation::Add(scalar_a, scalar_b) if **scalar_a == ScalarOperation::Zero => {
                self.scalar_operation(scalar_b)
            }

            ScalarOperation::Zero => (),
            ScalarOperation::Mul(scalar_op, _evaluation) => {
                self.mul_scalar();
                self.scalar_operation(scalar_op);
            }
            ScalarOperation::MulS(scalar_a, scalar_b) => {
                self.mul_scalar();
                self.scalar_operation(scalar_a);
                self.scalar_operation(scalar_b);
            }
            ScalarOperation::Power(_name, _exponent) => {
                // All powers of `v` and `u` are pre-computed to avoid duplication
                // so here instead of calling `scale(v, X)` we just refer to `vX` variable
                // format!("scale({}, {})", name, exponent)
                ()
            }
            ScalarOperation::Add(scalar_a, scalar_b) => {
                self.add_scalar();
                self.scalar_operation(scalar_a);
                self.scalar_operation(scalar_b);
            }
            ScalarOperation::Rotation(_) => (),
        }
    }

    pub(crate) fn expression(&mut self, exp: &Expression<Scalar>) {
        match exp {
            Expression::Advice(_) => (),
            Expression::Challenge(_) => (),
            Expression::Constant(_) => self.from_int_scalar(),
            Expression::Fixed(_) => (),
            Expression::Instance(_) => (),
            Expression::Negated(next_exp) => {
                self.neg_scalar();
                self.expression(next_exp);
            }
            Expression::Product(next_exp, last_exp) => {
                self.mul_scalar();
                self.expression(next_exp);
                self.expression(last_exp);
            }
            Expression::Scaled(next_exp, _) => {
                self.mul_scalar();
                self.expression(next_exp);
            }
            Expression::Selector(_) => (),
            Expression::Sum(next_exp, last_exp) => {
                self.add_scalar();
                self.expression(next_exp);
                self.expression(last_exp)
            }
        }
    }

    pub(crate) fn point_expression(&mut self, exp: &ExpressionG1<Scalar>) {
        match exp {
            ExpressionG1::Scale(next_exp, last_exp) => {
                self.scale();
                self.point_expression(next_exp);
                self.scalar_expression(last_exp);
            }
            ExpressionG1::Sum(next_exp, last_exp) => {
                self.add_point();
                self.point_expression(next_exp);
                self.point_expression(last_exp);
            }
            ExpressionG1::VanishingSplit(_) => (),
            ExpressionG1::Variable(_) => (),
            ExpressionG1::Zero => (),
        }
    }

    pub(crate) fn scalar_expression(&mut self, exp: &ScalarExpression<Scalar>) {
        match exp {
            ScalarExpression::Advice(_) => (),
            ScalarExpression::Constant(_) => self.from_int_scalar(),
            ScalarExpression::Fixed(_) => (),
            ScalarExpression::Instance(_) => (),
            ScalarExpression::Negated(_) => self.neg_scalar(),
            ScalarExpression::PermutationCommon(_) => (),
            ScalarExpression::PowMod(next_exp, _) => {
                self.pow_scalar();
                self.scalar_expression(next_exp);
            }
            ScalarExpression::Product(next_exp, last_exp) => {
                self.mul_scalar();
                self.scalar_expression(next_exp);
                self.scalar_expression(last_exp);
            }
            ScalarExpression::Sum(next_exp, last_exp) => {
                self.add_scalar();
                self.scalar_expression(next_exp);
                self.scalar_expression(last_exp);
            }
            ScalarExpression::Variable(_) => (),
        }
    }

    pub(crate) fn lagrange_polynomial_basis(&mut self, range: usize) {
        self.mul_scalar();
        self.sub_scalar();
        (1..=range).for_each(|_| {
            self.sub_scalar(); // sub(x, rotated_omega) 
            self.inv_scalar(); // batch_inverses
            self.mul_scalar(); // mul(inv, common)
            self.mul_scalar(); // mul(<prev>, rotated_omega)
        });
    }

    pub(crate) fn inner_product(&mut self, size: usize) {
        (0..size).for_each(|_| {
            self.add_scalar();
            self.mul_scalar();
        });
    }

    pub(crate) fn read_scalar(&mut self) {
        self.transcript_size -= 32;
        self.from_bytes_scalar += 1;
    }

    pub(crate) fn common_scalar(&mut self) {
        self.to_bytes_scalar += 1;
    }

    pub(crate) fn read_point(&mut self) {
        self.transcript_size -= 48;
        self.from_bytes_point += 1;
        self.decompress_point += 1;
    }

    pub(crate) fn squeeze_challenge(&mut self) {
        self.hash.push(self.transcript_size.max(0) as usize);
    }

    pub(crate) fn rotate_omega(&mut self) {
        self.add_scalar += 1;
        self.mul_scalar += 1;
    }

    pub(crate) fn scale(&mut self) {
        self.mul_point += 1;
    }

    pub(crate) fn add_point(&mut self) {
        self.add_point += 1;
    }

    pub(crate) fn decompress_point(&mut self) {
        self.decompress_point += 1;
    }

    pub(crate) fn compress_point(&mut self) {
        self.compress_point += 1;
    }

    pub(crate) fn neg_scalar(&mut self) {
        self.neg_scalar += 1;
    }

    pub(crate) fn add_scalar(&mut self) {
        self.add_scalar += 1;
    }

    pub(crate) fn sub_scalar(&mut self) {
        self.sub_scalar += 1;
    }

    pub(crate) fn mul_scalar(&mut self) {
        self.mul_scalar += 1;
    }

    pub(crate) fn inv_scalar(&mut self) {
        self.inv_scalar += 1;
    }

    pub(crate) fn pow_scalar(&mut self) {
        self.pow_scalar += 1;
    }

    pub(crate) fn from_int_scalar(&mut self) {
        self.from_int_scalar += 1;
    }
}
