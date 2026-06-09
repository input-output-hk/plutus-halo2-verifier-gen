use crate::plutus_gen::stats::chips::types;

impl std::fmt::Display for CircuitStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const W: usize = 30;
        writeln!(f, "{:=^40}", " Circuit Summary ")?;
        writeln!(f, "  {:<W$} {}", "degree:", self.degree)?;
        writeln!(f, "  {:<W$} {} bytes", "proof:", self.proof_size)?;
        writeln!(f, "  {:<W$} {} bytes", "vk:", self.vk_size)?;
        writeln!(f, "  {:<W$} {}", "public inputs:", self.public_inputs)?;
        writeln!(
            f,
            "  {:<W$} {}",
            "committed instances:", self.committed_instances
        )?;

        writeln!(f, "\n")?;
        writeln!(f, "{:=^40}", " Circuit Operations ")?;
        writeln!(f, "{:=^40}", " Transcript ")?;
        writeln!(f, "  {:<W$} {:?}", "hash :", self.hash.len())?;
        writeln!(
            f,
            "  {:<W$} {:?} bytes",
            "max input size :",
            self.hash.iter().max().unwrap_or(&0)
        )?;
        writeln!(f, "{:=^40}", " Scalar ops ")?;
        writeln!(
            f,
            "  {:<W$} {} / {} / {}",
            "add/sub/neg:", self.add_scalar, self.sub_scalar, self.neg_scalar
        )?;
        writeln!(
            f,
            "  {:<W$} {} / {} / {}",
            "mul/inv/pow:", self.mul_scalar, self.inv_scalar, self.pow_scalar
        )?;
        writeln!(
            f,
            "  {:<W$} {} / {}",
            "to/from_bytes:", self.to_bytes_scalar, self.from_bytes_scalar
        )?;
        writeln!(f, "  {:<W$} {}", "from_int:", self.from_int_scalar)?;
        writeln!(f, "{:=^40}", " Point ops ")?;
        writeln!(
            f,
            "  {:<W$} {} / {}",
            "add/mul:", self.add_point, self.mul_point
        )?;
        writeln!(
            f,
            "  {:<W$} {} / {}",
            "decomp/compress:", self.decompress_point, self.compress_point
        )?;
        writeln!(f, "  {:<W$} {}", "from_bytes:", self.from_bytes_point)?;
        writeln!(f, "  {:<W$} {:?}", "MSM sizes:", self.msm)?;
        writeln!(f, "{:=^40}", " Pairing ")?;
        writeln!(f, "  {:<W$} {}", "Miller loop:", self.miller_loop)?;
        write!(f, "  {:<W$} {}", "pairing:", self.pairing)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CircuitStatistics {
    pub(crate) transcript_size: usize,
    pub(crate) public_inputs: usize,
    pub(crate) committed_instances: usize,
    pub(crate) proof_size: usize,
    pub(crate) vk_size: usize,
    pub(crate) degree: usize,
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
    pub(crate) msm: Vec<usize>,
    pub(crate) from_bytes_point: usize,
    pub(crate) decompress_point: usize,
    pub(crate) compress_point: usize,
    pub(crate) miller_loop: usize,
    pub(crate) pairing: usize,
}

impl CircuitStatistics {
    pub(crate) fn new(
        proof_size: usize,
        vk_size: usize,
        degree: usize,
        public_inputs: usize,
        committed_instances: usize,
    ) -> Self {
        CircuitStatistics {
            transcript_size: 0,
            public_inputs,
            committed_instances,
            proof_size,
            vk_size,
            degree,
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
            msm: Vec::<usize>::new(),
            from_bytes_point: 0,
            decompress_point: 0,
            compress_point: 0,
            miller_loop: 2,
            pairing: 1,
        }
    }

    pub(crate) fn consume_expression(&mut self, exp: &types::expression::ScalarExpression) {
        (0..exp.ops.nb_neg).for_each(|_| self.neg_scalar());
        (0..exp.ops.nb_add).for_each(|_| self.add_scalar());
        (0..exp.ops.nb_sub).for_each(|_| self.sub_scalar());
        (0..exp.ops.nb_mul).for_each(|_| self.mul_scalar());
        (0..exp.ops.nb_from_int).for_each(|_| self.from_int_scalar());
    }

    pub(crate) fn lagrange_polynomial_basis(&mut self, range: usize) {
        // Step 1: common = mul(sub_int(xn, 1), barycentric_weight)
        self.mul_scalar();

        // Step 2: compute [(x - ω_i^{-1})] by batch inversion
        // TODO when CIP-109 is implemented, inverting each ω_i should be cheaper
        (1..=range).for_each(|_| {
            self.sub_scalar(); // sub(x, rotated_omega)
        });
        self.batch_inversion(range);

        // Step 3: compute  [ω_i * common * (x - ω_i)^{-1}]
        (1..=range).for_each(|_| {
            self.mul_scalar(); // mul(inv, common)
            self.mul_scalar(); // mul(<prev>, rotated_omega)
        });
    }

    pub(crate) fn lagrange_evaluation(&mut self, size: usize) {
        // Step 1: compute numerators and denominators for all points
        // As we skip some inner steps depending on the scalar values, we simplify the cost function and overestimate it here.
        (0..size).for_each(|_| {
            (0..size - 1).for_each(|_| {
                (0..2).for_each(|_| self.sub_scalar());
                (0..2).for_each(|_| self.mul_scalar());
            });
        });

        // Step 2: batch invert denominators
        // TODO when CIP-109 is implemented, inverting each element should be cheaper
        self.batch_inversion(size);

        // Step 3: aggregating
        (0..size).for_each(|_| {
            self.add_scalar();
            (0..2).for_each(|_| self.mul_scalar());
        });
    }

    pub(crate) fn inner_product(&mut self, size: usize) {
        (0..size).for_each(|_| {
            self.add_scalar();
            self.mul_scalar();
        });
    }

    pub(crate) fn batch_inversion(&mut self, size: usize) {
        // Step 1: build reversed cumulative products
        (0..(size - 1)).for_each(|_| {
            self.mul_scalar();
        });

        // Step 2: single inversion of common denom
        self.inv_scalar();

        // Step 3: find all other inverses
        (0..(size - 1)).for_each(|_| {
            self.mul_scalar();
            self.mul_scalar();
        });
    }

    pub(crate) fn read_scalar(&mut self) {
        self.transcript_size += 32;
        self.from_bytes_scalar += 1;
    }

    pub(crate) fn common_scalar(&mut self) {
        self.to_bytes_scalar += 1;
        self.transcript_size += 32;
    }

    pub(crate) fn read_point(&mut self) {
        self.transcript_size += 48;
        self.from_bytes_point += 1;
        self.decompress_point += 1;
    }

    pub(crate) fn common_g1(&mut self) {
        self.transcript_size += 48;
    }

    pub(crate) fn squeeze_challenge(&mut self) {
        // To make sure the challenge is uniformly random,
        // we hashed twice and batched the digests together
        // For simplicity however, we only show one hash
        self.hash.push(self.transcript_size);
        // self.hash.push(self.transcript_size);
        // self.from_bytes_scalar +=1;
        self.from_bytes_scalar += 2;
    }

    pub(crate) fn rotate_omega(&mut self) {
        self.pow_scalar += 1;
        self.mul_scalar += 1;
    }

    pub(crate) fn msm(&mut self, size: usize) {
        self.msm.push(size);
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
