{-# LANGUAGE Strict #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Constants where

import Plutus.Crypto.BlsTypes (Scalar, bls12_381_field_prime, mkScalar)
import PlutusTx.Prelude (modulo)

-- this is constant from halo2 "halo2_proofs::halo2curves::bls12_381::Scalar::DELTA"
scalarDelta :: Scalar
scalarDelta =
    mkScalar
        (0x08634d0aa021aaf843cab354fabb0062f6502437c6a09c006c083479590189d7 `modulo` bls12_381_field_prime)

-- this is constant from halo2 "halo2_proofs::halo2curves::bls12_381::Scalar::ONE"
scalarOne :: Scalar
scalarOne =
    mkScalar
        (0x0000000000000000000000000000000000000000000000000000000000000001 `modulo` bls12_381_field_prime)

-- this is constant from halo2 "halo2_proofs::halo2curves::bls12_381::Scalar::ZERO"
scalarZero :: Scalar
scalarZero =
    mkScalar
        (0x0000000000000000000000000000000000000000000000000000000000000000 `modulo` bls12_381_field_prime)
