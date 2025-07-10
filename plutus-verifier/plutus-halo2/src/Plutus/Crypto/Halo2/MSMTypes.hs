{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.MSMTypes (
    MinimalVerifierQuery (MinimalVerifierQuery, mv_commitment, mv_eval),
    MSMElem (MSMElem),
    MSM (MSM),
    addMSM,
    appendTerm,
    scaleMSM,
) where

import Plutus.Crypto.BlsTypes (Scalar)
import PlutusTx.List (
    map,
    (++),
 )
import PlutusTx.Prelude (
    BuiltinBLS12_381_G1_Element,
    (*),
 )
import qualified Prelude as Haskell

data MinimalVerifierQuery = MinimalVerifierQuery
    { -- Commitment
      mv_commitment :: BuiltinBLS12_381_G1_Element
    , -- Evaluation of polynomial at query point
      mv_eval :: Scalar
    }
    deriving (Haskell.Eq)

newtype MSMElem = MSMElem (Scalar, BuiltinBLS12_381_G1_Element)
newtype MSM = MSM [MSMElem]

deriving instance (Haskell.Eq MSMElem)
deriving instance (Haskell.Eq MSM)

{-# INLINEABLE addMSM #-}
addMSM :: MSM -> MSM -> MSM
addMSM (MSM !s1) (MSM !s2) =
    MSM (s1 ++ s2)

{-# INLINEABLE appendTerm #-}
appendTerm :: MSM -> MSMElem -> MSM
appendTerm (MSM !l) !elem = MSM (elem : l)

{-# INLINEABLE scaleMSM #-}
scaleMSM :: Scalar -> MSM -> MSM
scaleMSM s (MSM es) = MSM result
  where
    result = map (\(MSMElem (scalar, g1)) -> MSMElem (s * scalar, g1)) es
