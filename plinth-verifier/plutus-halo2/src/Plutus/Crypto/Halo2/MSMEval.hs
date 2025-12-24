{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.MSMEval (eval) where

import Plutus.Crypto.Halo2.MSMTypes (MSM (MSM), MSMElem (MSMElem))

import PlutusTx.List (foldl)
import PlutusTx.Prelude (
    AdditiveSemigroup ((+)),
    BuiltinBLS12_381_G1_Element,
    Module (scale),
    bls12_381_G1_compressed_zero,
    bls12_381_G1_uncompress,
    uncurry,
 )

-- todo optimize when there will be native support for MSM
{-# INLINEABLE eval #-}
eval :: MSM -> BuiltinBLS12_381_G1_Element
eval (MSM zipped) =
    foldl
        (\accum (MSMElem elem) -> accum + scale' elem)
        (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)
        zipped
  where
    !scale' = uncurry scale
