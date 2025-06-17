{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.Proof (
    readPoint,
    readScalar,
    readByteString,
    Proof,
)
where

import GHC.ByteOrder (ByteOrder (..))
import Plutus.Crypto.BlsTypes (
    Scalar,
    mkScalar,
 )
import PlutusTx.Builtins (
    byteStringToInteger,
 )
import PlutusTx.Numeric (
    MultiplicativeSemigroup ((*)),
 )
import PlutusTx.Prelude (
    BuiltinBLS12_381_G1_Element,
    BuiltinByteString,
    Integer,
    bls12_381_G1_uncompress,
    lengthOfByteString,
    sliceByteString,
    traceError,
    ($),
    (==),
 )

type Proof = BuiltinByteString

maxProofLength :: Integer
maxProofLength = 16384

{-# INLINEABLE readByteString #-}
readByteString :: Integer -> Proof -> (BuiltinByteString, Proof)
readByteString !bytesToRead transcript =
    let !read = sliceByteString 0 bytesToRead transcript
        !len = lengthOfByteString read
     in if len == bytesToRead
            then (read, sliceByteString bytesToRead maxProofLength transcript)
            else traceError "Not enought bytes to read"

dwordSizeInBytes :: Integer
dwordSizeInBytes = 8

scalarSizeInDWords :: Integer
scalarSizeInDWords = 4

compressedPointSizeInDWords :: Integer
compressedPointSizeInDWords = 6

{-# INLINE readScalar #-}
readScalar :: Proof -> (Scalar, Proof)
readScalar transcript =
    let (bs, transcript') = readByteString (dwordSizeInBytes * scalarSizeInDWords) transcript
     in -- assuming that byteStringToInteger uses le order
        (mkScalar $ byteStringToInteger LittleEndian bs, transcript')

{-# INLINE readPoint #-}
readPoint :: Proof -> (BuiltinBLS12_381_G1_Element, Proof)
readPoint transcript =
    let (bs, transcript') = readByteString (dwordSizeInBytes * compressedPointSizeInDWords) transcript
     in (bls12_381_G1_uncompress bs, transcript')
