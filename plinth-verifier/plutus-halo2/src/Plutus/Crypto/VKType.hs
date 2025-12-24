{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Plutus.Crypto.VKType (
    BigUInteger (BigUInteger),
    G1Affine (G1Affine),
    ColumnIndex (ColumnIndex),
    Rotation (Rotation),
    ConstraintSystem (ConstraintSystem),
    EvaluationDomain (EvaluationDomain),
    VerifyingKey (VerifyingKey),
    Vk,
    VkRepr,
    coerceVK,
)
where

import Data.Aeson (FromJSON (parseJSON))
import GHC.Base (coerce)
import GHC.Generics (Generic)
import Plutus.Crypto.BlsTypes (Fp, Scalar, mkFp, mkScalar)
import Text.Read (readMaybe)

newtype BigUInteger = BigUInteger {unBigUInteger :: Integer}
    deriving (Show)

instance FromJSON BigUInteger where
    parseJSON value = do
        intAsString <- parseJSON @String value
        let maybeInt = readMaybe @Integer intAsString
        int <- maybe (fail "Cannot parse BigUInteger") pure maybeInt
        pure $ BigUInteger int

newtype FpW = FpW {unFpW :: Fp}
    deriving (Show)

instance FromJSON FpW where
    parseJSON value = FpW . mkFp . unBigUInteger <$> parseJSON @BigUInteger value

newtype ScalarW = ScalarW {unScalarW :: Scalar}
    deriving (Show)

instance FromJSON ScalarW where
    parseJSON value = ScalarW . mkScalar . unBigUInteger <$> parseJSON @BigUInteger value

data G1Affine fp = G1Affine
    { x :: fp
    , y :: fp
    }
    deriving (Generic, Show)

instance (FromJSON a) => FromJSON (G1Affine a)

newtype ColumnIndex = ColumnIndex Integer
    deriving (Generic, Show)

instance FromJSON ColumnIndex

newtype Rotation = Rotation Integer
    deriving (Generic, Show)

instance FromJSON Rotation

data ConstraintSystem = ConstraintSystem
    { advice_queries :: [(ColumnIndex, Rotation)]
    , fixed_queries :: [(ColumnIndex, Rotation)]
    , blinding_factors :: Integer
    }
    deriving (Generic, Show)

instance FromJSON ConstraintSystem

data EvaluationDomain scalar = EvaluationDomain
    { omega :: scalar
    , omega_inv :: scalar
    }
    deriving (Generic, Show)

instance (FromJSON scalar) => FromJSON (EvaluationDomain scalar)

data VerifyingKey fp scalar = VerifyingKey
    { transcript_repr :: scalar
    , fixed_commitments :: [G1Affine fp]
    , permutation :: [G1Affine fp]
    , cs :: ConstraintSystem
    , domain :: EvaluationDomain scalar
    }
    deriving (Generic, Show)

instance (FromJSON fp, FromJSON scalar) => FromJSON (VerifyingKey fp scalar)

type Vk = VerifyingKey Fp Scalar

type VkRepr = VerifyingKey FpW ScalarW

coerceVK :: VkRepr -> Vk
coerceVK = coerce
