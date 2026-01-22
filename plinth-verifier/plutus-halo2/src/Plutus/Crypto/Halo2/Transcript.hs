{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.Transcript (
    Transcript,
    squeezeChallange,
    addScalarToTranscript,
    addPointToTranscript,
    addCommonScalarToTranscript,
)
where

import GHC.ByteOrder (ByteOrder (..))
import Plutus.Crypto.BlsTypes (
    Scalar,
    bls12_381_field_prime,
    mkScalar,
    unScalar,
 )
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinByteString,
    blake2b_256,
    bls12_381_G1_compress,
    byteStringToInteger,
    consByteString,
    emptyByteString,
    integerToByteString,
 )
import PlutusTx.Prelude (
    Semigroup ((<>)),
    modulo,
    (*),
    (+)
 )

-- todo constants from rust implementation of halo2
-- /// Prefix to a prover's message soliciting a challenge
-- const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;
--
-- /// Prefix to a prover's message containing a curve point
-- const BLAKE2B_PREFIX_POINT: u8 = 1;
--
-- /// Prefix to a prover's message containing a scalar
-- const BLAKE2B_PREFIX_SCALAR: u8 = 2;
--

-- /// Prefix to a prover's message soliciting a challenge
-- const KECCAK256_PREFIX_CHALLENGE: u8 = 0;
--
-- /// First prefix to a prover's message soliciting a challenge
--  /// Not included in the growing state!
-- const KECCAK256_PREFIX_CHALLENGE_LO: u8 = 10;
--
-- /// Second prefix to a prover's message soliciting a challenge
--  /// Not included in the growing state!
-- const KECCAK256_PREFIX_CHALLENGE_HI: u8 = 11;
--
-- /// Prefix to a prover's message containing a curve point
-- const KECCAK256_PREFIX_POINT: u8 = 1;
--
-- /// Prefix to a prover's message containing a scalar
-- const KECCAK256_PREFIX_SCALAR: u8 = 2;

-- transcript is concatenated bytes and below are methods for translating components into bytes with concatenation
type Transcript = BuiltinByteString

blake2bPrefixChallenge :: BuiltinByteString
blake2bPrefixChallenge = consByteString 0 emptyByteString

blake2bPrefixCommon :: BuiltinByteString
blake2bPrefixCommon = consByteString 1 emptyByteString

{-# INLINEABLE addCommonScalarToTranscript #-}
addCommonScalarToTranscript :: Transcript -> Scalar -> Transcript
addCommonScalarToTranscript bs s = bs <> blake2bPrefixCommon <> (integerToByteString LittleEndian 32 (unScalar s))

-- this is the constant 2^256 % q
scalarR :: Scalar
scalarR = mkScalar (0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe `modulo` bls12_381_field_prime)

-- labels are fixed comparing to plonk poc?
{-# INLINEABLE squeezeChallange #-}
squeezeChallange :: Transcript -> (Scalar, Transcript)
squeezeChallange bs =
    let hash = blake2b_256 (bs <> blake2bPrefixChallenge) in
    let re_hash = blake2b_256 hash in
    let scalar1 = mkScalar ( byteStringToInteger LittleEndian hash `modulo` bls12_381_field_prime ) in
    let scalar2 = mkScalar ( byteStringToInteger LittleEndian re_hash `modulo` bls12_381_field_prime ) in
    ( scalar1 + scalarR * scalar2
    , bs <> blake2bPrefixChallenge
    )

{-# INLINEABLE addPointToTranscript #-}
addPointToTranscript :: Transcript -> BuiltinBLS12_381_G1_Element -> Transcript
addPointToTranscript bs point =
    bs
        <> blake2bPrefixCommon
        <> bls12_381_G1_compress point

{-# INLINEABLE addScalarToTranscript #-}
addScalarToTranscript :: Transcript -> Scalar -> Transcript
addScalarToTranscript bs s = bs <> blake2bPrefixCommon <> (integerToByteString LittleEndian 32 (unScalar s))
