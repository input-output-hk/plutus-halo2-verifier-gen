{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.CompressUncompress (
    compressG1Point,
    unCompressG1Point,
) where

import GHC.ByteOrder (ByteOrder (..))
import Plutus.Crypto.BlsTypes (
    Fp (Fp, unFp),
    Fp2 (Fp2, imaginary, real),
    bls12_381_base_prime,
    div,
    pow,
    reverseByteString,
 )

import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
    BuiltinByteString,
    bls12_381_G1_compress,
    bls12_381_G1_compressed_zero,
    bls12_381_G1_uncompress,
    bls12_381_G2_compress,
    bls12_381_G2_compressed_zero,
    bls12_381_G2_uncompress,
    byteStringToInteger,
    integerToByteString,
    readBit,
    sliceByteString,
    writeBits,
 )
import PlutusTx.List (foldr)
import PlutusTx.Numeric (
    negate,
 )
import PlutusTx.Prelude (
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Bool (..),
    Eq (..),
    Integer,
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
    Ord ((<)),
    divide,
    not,
    otherwise,
    ($),
    (&&),
    (.),
    (>),
    (||),
 )

setPrefix :: BuiltinByteString -> Bool -> Bool -> Bool -> BuiltinByteString
setPrefix bs b1 b2 b3 = result
  where
    p1 = writeBitByteString bs 7 b1
    p2 = writeBitByteString p1 6 b2
    result = writeBitByteString p2 5 b3

writeBitByteString :: BuiltinByteString -> Integer -> Bool -> BuiltinByteString
writeBitByteString bs idx val = writeBits bs [idx] val

testBitByteString :: BuiltinByteString -> Integer -> Bool
testBitByteString bs idx = readBit bs idx

g1_zero :: BuiltinBLS12_381_G1_Element
g1_zero = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)

g2_zero :: BuiltinBLS12_381_G2_Element
g2_zero = (bls12_381_G2_uncompress bls12_381_G2_compressed_zero)

{-# INLINEABLE compressG1Point #-}
compressG1Point :: (Fp, Fp) -> BuiltinBLS12_381_G1_Element
compressG1Point (Fp x, Fp y) | x == 0 && y == 1 = g1_zero
compressG1Point (x, y) = result
  where
    x_bs = integerToByteString LittleEndian 48 (unFp x)
    prefixed =
        if y < negate y
            then --          0x8 => 100
                setPrefix x_bs True False False
            else --          0xa => 101
                setPrefix x_bs True False True
    result = bls12_381_G1_uncompress (reverseByteString prefixed)

{-# INLINEABLE unCompressG1Point #-}
unCompressG1Point :: BuiltinBLS12_381_G1_Element -> (Fp, Fp)
unCompressG1Point p
    | p == g1_zero = (zero, one)
    | otherwise = (x, y')
  where
    p' = reverseByteString . bls12_381_G1_compress $ p
    --            check for Y coordinate in point compression
    --            out[0] |= (unsigned char)(0x80 | ((sign & 2) << 4));
    !sixthBit = testBitByteString p' 5 -- check 6th bit for
    !x =
        Fp
            . byteStringToInteger LittleEndian
            $ foldr (\i acc -> writeBitByteString acc i False) p' [7, 6, 5] -- last 3 bits of first word as first 3 bits
    !y = scale ((bls12_381_base_prime + 1) `divide` 4) (x * x * x + Fp 4)
    --            based on compression info add correct Y coordinate
    y' = if (sixthBit && y < negate y) || (not sixthBit && y > negate y) then negate y else y
