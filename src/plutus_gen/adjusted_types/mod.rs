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
pub struct CardanoFriendlyState {
    state: State,
}

/// this setup is due to Cardano proving blake2b 256 as builtin
impl TranscriptHash for CardanoFriendlyState {
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
        let mut padded_result: [u8; 64] = [0; 64];
        padded_result[..32].copy_from_slice(result);
        padded_result.to_vec()
    }
}

/// standard implementation for Scalar is used as only thing I had to changes was hash setup
impl Hashable<CardanoFriendlyState> for Scalar {
    fn to_input(&self) -> <CardanoFriendlyState as TranscriptHash>::Input {
        // <Scalar as Hashable<State>>::to_input(self)
        self.to_repr().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        // <Scalar as Hashable<State>>::to_bytes(self)
        self.to_repr().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        // <Scalar as Hashable<State>>::read(buffer)
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

/// standard implementation for Scalar is used as only thing I had to changes was hash setup
impl Sampleable<CardanoFriendlyState> for Scalar {
    fn sample(hash_output: <CardanoFriendlyState as TranscriptHash>::Output) -> Self {
        // <Scalar as Sampleable<State>>::sample(hash_output)
        assert!(hash_output.len() <= 64);
        assert!(hash_output.len() >= (Scalar::NUM_BITS as usize / 8) + 12);
        let mut bytes = [0u8; 64];
        bytes[..hash_output.len()].copy_from_slice(&hash_output);
        Scalar::from_uniform_bytes(&bytes)
    }
}

/// standard implementation for Scalar is used as only thing I had to changes was hash setup
impl Hashable<CardanoFriendlyState> for G1Projective {
    fn to_input(&self) -> <CardanoFriendlyState as TranscriptHash>::Input {
        // <G1Projective as Hashable<State>>::to_input(self)
        Hashable::<State>::to_bytes(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        // <G1Projective as Hashable<State>>::to_bytes(self)
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        // <G1Projective as Hashable<State>>::read(buffer)
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
