use blake2b_simd::{Params, State};
use blstrs::{G1Projective, Scalar};
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::group::{Curve, GroupEncoding};
use halo2_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use std::io;
use std::io::Read;
use log::info;

const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;

/// Prefix to a prover's message
const BLAKE2B_PREFIX_COMMON: u8 = 1;

#[derive(Debug)]
pub struct CardanoFriendlyState {
    state: State,
}

impl TranscriptHash for CardanoFriendlyState {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn init() -> Self {
        Self {
            state: Params::new().hash_length(32).to_state(),
        }
    }
    fn absorb(&mut self, input: &Self::Input) {
        info!("adding to transcript {:?}", hex::encode(input.clone()));
        self.state.update(&[BLAKE2B_PREFIX_COMMON]);
        self.state.update(input);
    }

    fn squeeze(&mut self) -> Self::Output {
        self.state.update(&[BLAKE2B_PREFIX_CHALLENGE]);
        let result = self.state.finalize();
        let result = result.as_bytes();
        let mut padded_result: [u8; 64] = [0; 64];
        padded_result[..32].copy_from_slice(result);
        padded_result.to_vec()
    }
}

impl Hashable<CardanoFriendlyState> for Scalar {
    fn to_input(&self) -> <CardanoFriendlyState as TranscriptHash>::Input {
        self.to_repr().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_repr().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as PrimeField>::Repr::default();

        buffer.read_exact(bytes.as_mut())?;

        Option::from(Self::from_repr(bytes))
            .ok_or_else(|| io::Error::other("Invalid BLS12-381 scalar encoding in proof"))
    }
}

impl Sampleable<CardanoFriendlyState> for Scalar {
    fn sample(hash_output: <CardanoFriendlyState as TranscriptHash>::Output) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..hash_output.len()].copy_from_slice(&hash_output);
        let s = Scalar::from_uniform_bytes(&bytes);

        info!("sampled {:?}", s);
        s
    }
}

impl Hashable<CardanoFriendlyState> for G1Projective {
    fn to_input(&self) -> <CardanoFriendlyState as TranscriptHash>::Input {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as GroupEncoding>::Repr::default();

        buffer.read_exact(bytes.as_mut())?;

        let p = Option::from(Self::from_bytes(&bytes))
            .ok_or_else(|| io::Error::other("Invalid BLS12-381 point encoding in proof"));

        println!(
            "got a point {:?}",
            p.iter()
                .clone()
                .map(<Self as Curve>::to_affine)
                .map(|affine| format!("x:{:?}  y:{:?}", affine.x(), affine.y()))
                .collect::<Vec<String>>()
        );

        p
    }
}
