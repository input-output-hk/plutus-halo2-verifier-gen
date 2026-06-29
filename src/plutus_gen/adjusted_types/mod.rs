use blake2b_simd::{Params, State};
use std::io;
use std::io::Read;

use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;

use midnight_curves::{BlsScalar as Scalar, G1Projective};
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};

/// Prefix when squeezing challenges from the transcript
const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;

/// Prefix when updating state with prover's messages
const BLAKE2B_PREFIX_COMMON: u8 = 1;

/// Cardano-compatible transcript implementation and related traits for
/// Fiat-Shamir transformation.
#[derive(Debug, Clone)]
pub struct CardanoFriendlyBlake2b {
    state: State,
}

/// Cardano-compatible transcript hash for Fiat-Shamir transformation.
///
/// This differs from halo2's default `blake2b_simd::State` implementation:
/// - Uses 32-byte outputs (blake2b-256) instead of 64-byte, since Plutus only
///   exposes `blake2b_256` builtin
/// - Unkeyed hash (no domain separator key), as Plutus doesn't support keyed
///   blake2b
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
        self.state.update(&[BLAKE2B_PREFIX_COMMON]);
        self.state.update(input);
    }

    fn squeeze(&mut self) -> Self::Output {
        self.state.update(&[BLAKE2B_PREFIX_CHALLENGE]);
        let result = self.state.finalize();
        let result = result.as_bytes();

        // Re-hashing the result to get 32 extra bytes for more randomness for
        // sampling challenges.
        let mut state = Params::new().hash_length(32).to_state();
        state.update(result);
        let digest = state.finalize();
        let re_hash = digest.as_bytes();

        let mut padded_result: [u8; 64] = [0; 64];
        padded_result[..32].copy_from_slice(result);
        padded_result[32..].copy_from_slice(re_hash);
        padded_result.to_vec()
    }
}


/// Standard implementation for Scalar sampling, done as in halo2
impl Sampleable<CardanoFriendlyBlake2b> for Scalar {
    fn sample(hash_output: <CardanoFriendlyBlake2b as TranscriptHash>::Output) -> Self {
        assert!(hash_output.len() <= 64);
        assert!(hash_output.len() >= (Scalar::NUM_BITS as usize / 8) + 12);
        let mut bytes = [0u8; 64];
        bytes[..hash_output.len()].copy_from_slice(&hash_output);
        Scalar::from_uniform_bytes(&bytes)
    }
}
