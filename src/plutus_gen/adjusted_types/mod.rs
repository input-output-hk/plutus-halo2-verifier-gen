use blake2b_simd::{Params, State};
use midnight_curves::{BlsScalar as Scalar, G1Projective};

use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use log::debug;
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use std::io;
use std::io::Read;

const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;

/// Prefix to a prover's message
const BLAKE2B_PREFIX_COMMON: u8 = 1;

#[derive(Debug, Clone)]
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

        // Re-hashing the result to get 32 extra bytes.
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

/// Standard implementation for Scalar as in halo2
impl Hashable<CardanoFriendlyBlake2b> for Scalar {
    fn to_input(&self) -> <CardanoFriendlyBlake2b as TranscriptHash>::Input {
        self.to_repr().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_repr().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as PrimeField>::Repr::default();

        buffer.read_exact(bytes.as_mut())?;

        Option::from(Self::from_repr(bytes)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Invalid BLS12-381 scalar encoding in proof",
            )
        })
    }
}

/// Standard implementation for Scalar as in halo2
impl Sampleable<CardanoFriendlyBlake2b> for Scalar {
    fn sample(hash_output: <CardanoFriendlyBlake2b as TranscriptHash>::Output) -> Self {
        assert!(hash_output.len() <= 64);
        assert!(hash_output.len() >= (Scalar::NUM_BITS as usize / 8) + 12);
        let mut bytes = [0u8; 64];
        bytes[..hash_output.len()].copy_from_slice(&hash_output);
        Scalar::from_uniform_bytes(&bytes)
    }
}

/// Standard implementation for G1Projective as in halo2
impl Hashable<CardanoFriendlyBlake2b> for G1Projective {
    fn to_input(&self) -> <CardanoFriendlyBlake2b as TranscriptHash>::Input {
        Hashable::<State>::to_bytes(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as GroupEncoding>::Repr::default();

        buffer.read_exact(bytes.as_mut())?;

        Option::from(Self::from_bytes(&bytes)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Invalid BLS12-381 point encoding in proof",
            )
        })
    }
}
