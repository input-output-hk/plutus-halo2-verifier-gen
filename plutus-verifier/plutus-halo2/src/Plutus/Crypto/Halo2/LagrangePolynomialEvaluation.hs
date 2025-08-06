{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.LagrangePolynomialEvaluation (
    lagrangePolynomialBasis,
    lagrangeEvaluation,
    basis,
) where

import Plutus.Crypto.BlsTypes (
    Scalar,
    recip,
 )
import PlutusTx.List (foldl, zip)
import PlutusTx.Prelude (
    AdditiveMonoid (..),
    MultiplicativeMonoid (one),
    fmap,
    ($),
    (*),
    (+),
    (-),
    (/=),
 )

{- | Computes evaluations (at the point `x`, where `xn = x^n`) of Lagrange
basis polynomials `l_i(X)` defined such that `l_i(omega^i) = 1` and
`l_i(omega^j) = 0` for all `j != i` at each provided rotation `i`.
this is equivalent to `l_i_range` from halo2 from src/poly/domain.rs
https://github.com/input-output-hk/halo2/blob/plutus_verification/src/poly/domain.rs#L405-L474
-}
{-# INLINEABLE lagrangePolynomialBasis #-}
lagrangePolynomialBasis ::
    -- | x
    Scalar ->
    -- | xn inverse
    Scalar ->
    -- | barycentric weight
    Scalar ->
    -- |  list of already rotated omegas
    [Scalar] ->
    [Scalar]
lagrangePolynomialBasis x xn barycentricWeight rotations = result
  where
    common :: Scalar
    !common = (xn - one) * barycentricWeight

    inversed :: [Scalar]
    !inversed = fmap (\rotatedOmega -> recip (x - rotatedOmega)) rotations

    result :: [Scalar]
    !result = fmap (\(inv, rotatedOmega) -> inv * common * rotatedOmega) $ zip inversed rotations

-- this function first does lagrange interpolation based on list of tuples,
-- where first element is treated as x and second as y
-- then it evaluates interpolated polynomial with 2nd argument of the function X
-- and returns interpolated_poly(x)
{-# INLINEABLE lagrangeEvaluation #-}
lagrangeEvaluation :: [(Scalar, Scalar)] -> Scalar -> Scalar
lagrangeEvaluation pts x =
    foldl
        (\acc (xi, yi) -> acc + yi * basis x xi pts)
        zero
        pts

{-# INLINEABLE basis #-}
basis :: Scalar -> Scalar -> [(Scalar, Scalar)] -> Scalar
basis x xi pts =
    let
        --        !_ =
        --            trace
        --                ( "calculating basis for x = "
        --                    <> show x
        --                    <> " xi = "
        --                    <> show xi
        --                    <> " pts = "
        --                    <> show pts
        --                )
        --                ()
        (totalNumerator, totalDenominator) =
            foldl
                ( \(numerator, denominator) (xj, _) ->
                    if xj /= xi
                        then (numerator * (x - xj), denominator * (xi - xj))
                        else (numerator, denominator)
                )
                (one, one)
                pts
     in
        totalNumerator * recip totalDenominator
