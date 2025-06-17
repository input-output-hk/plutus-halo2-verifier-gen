{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Plutus.Crypto.Orphans where

import qualified Language.Haskell.TH.Syntax as TH

import GHC.ByteOrder (ByteOrder (..))

import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
    bls12_381_G1_compress,
    bls12_381_G1_uncompress,
    bls12_381_G2_compress,
    bls12_381_G2_uncompress,
    byteStringToInteger,
    integerToByteString,
 )

-- lifts for encoding constants to plutus script
instance TH.Lift BuiltinBLS12_381_G1_Element where
    liftTyped point =
        [||bls12_381_G1_uncompress (integerToByteString LittleEndian 48 asInteger)||]
      where
        asBS = bls12_381_G1_compress point
        asInteger = byteStringToInteger LittleEndian asBS

instance TH.Lift BuiltinBLS12_381_G2_Element where
    liftTyped point =
        [||bls12_381_G2_uncompress (integerToByteString LittleEndian 96 asInteger)||]
      where
        asBS = bls12_381_G2_compress point
        asInteger = byteStringToInteger LittleEndian asBS
