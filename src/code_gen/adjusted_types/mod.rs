use blake2b_simd::{Params, State};
use blstrs::{G1Projective, Scalar};
use halo2_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use std::io;
use std::io::Read;
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
        <Scalar as Hashable<State>>::to_input(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Scalar as Hashable<State>>::to_bytes(self)
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        <Scalar as Hashable<State>>::read(buffer)
    }
}

impl Sampleable<CardanoFriendlyState> for Scalar {
    fn sample(hash_output: <CardanoFriendlyState as TranscriptHash>::Output) -> Self {
        <Scalar as Sampleable<State>>::sample(hash_output)
    }
}

impl Hashable<CardanoFriendlyState> for G1Projective {
    fn to_input(&self) -> <CardanoFriendlyState as TranscriptHash>::Input {
        <G1Projective as Hashable<State>>::to_input(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        <G1Projective as Hashable<State>>::to_bytes(self)
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        <G1Projective as Hashable<State>>::read(buffer)
    }
}
