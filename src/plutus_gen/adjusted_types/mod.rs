use blake2b_simd::{Params, State};
use blstrs::{G1Projective, Scalar};
use halo2_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use log::debug;
use std::io;
use std::io::Read;

const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;

/// Prefix to a prover's message
const BLAKE2B_PREFIX_COMMON: u8 = 1;

#[derive(Debug)]
pub struct CardanoFriendlyBlake2b {
    state: State,
}

/// Cardano-compatible transcript hash for Fiat-Shamir transformation.
///
/// This differs from halo2's default `blake2b_simd::State` implementation:
/// - Uses 32-byte output (blake2b-256) instead of 64-byte, since Plutus only exposes `blake2b_256` builtin
/// - Unkeyed hash (no domain separator key), as Plutus doesn't support keyed blake2b
/// - Output is zero-padded to 64 bytes to satisfy `Sampleable` requirements for field element sampling
///
/// The prefix bytes (0x00 for squeeze, 0x01 for absorb) match halo2's domain separation scheme.
impl TranscriptHash for CardanoFriendlyBlake2b {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn init() -> Self {
        Self {
            state: Params::new().hash_length(32).to_state(),
        }
    }
    fn absorb(&mut self, input: &Self::Input) {
        debug!("adding to transcript {:?}", hex::encode(input.clone()));
        self.state.update(&[BLAKE2B_PREFIX_COMMON]);
        self.state.update(input);
    }

    fn squeeze(&mut self) -> Self::Output {
        self.state.update(&[BLAKE2B_PREFIX_CHALLENGE]);
        let result = self.state.finalize();
        let result = result.as_bytes();
        // TODO: consider to use double-hashing to expand to 64 bytes instead of zero-padding,
        //       although this might increase on-chain cost.
        let mut padded_result: [u8; 64] = [0; 64];
        padded_result[..32].copy_from_slice(result);
        padded_result.to_vec()
    }
}

/// Standard implementation for Scalar as in halo2
impl Hashable<CardanoFriendlyBlake2b> for Scalar {
    fn to_input(&self) -> <CardanoFriendlyBlake2b as TranscriptHash>::Input {
        <Scalar as Hashable<State>>::to_input(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Scalar as Hashable<State>>::to_bytes(self)
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        <Scalar as Hashable<State>>::read(buffer)
    }
}

/// Standard implementation for Scalar as in halo2
impl Sampleable<CardanoFriendlyBlake2b> for Scalar {
    fn sample(hash_output: <CardanoFriendlyBlake2b as TranscriptHash>::Output) -> Self {
        <Scalar as Sampleable<State>>::sample(hash_output)
    }
}

/// Standard implementation for G1Projective as in halo2
impl Hashable<CardanoFriendlyBlake2b> for G1Projective {
    fn to_input(&self) -> <CardanoFriendlyBlake2b as TranscriptHash>::Input {
        <G1Projective as Hashable<State>>::to_input(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        <G1Projective as Hashable<State>>::to_bytes(self)
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        <G1Projective as Hashable<State>>::read(buffer)
    }
}
