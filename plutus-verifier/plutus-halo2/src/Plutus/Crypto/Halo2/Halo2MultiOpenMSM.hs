{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.Halo2MultiOpenMSM (
    buildMSM,
    buildQ,
    computeV,
    evaluateLagrangePolynomials,
    finalCommitment,
    x1PowersCount,
) where

import Plutus.Crypto.BlsTypes (
    Scalar,
    recip,
 )
import Plutus.Crypto.BlsUtils (
    powers,
 )
import Plutus.Crypto.Halo2.LagrangePolynomialEvaluation (
    lagrangeEvaluation,
 )
import Plutus.Crypto.Halo2.MSMTypes (
    MSM (..),
    MSMElem (MSMElem),
    addMSM,
    appendTerm,
    scaleMSM,
 )
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
 )
import PlutusTx.List (
    filter,
    foldl,
    length,
    map,
    reverse,
    unzip,
    zip,
    (++),
 )
import PlutusTx.Prelude (
    Integer,
    bls12_381_G1_compressed_generator,
    bls12_381_G1_neg,
    bls12_381_G1_uncompress,
    enumFromTo,
    max,
    one,
    trace,
    zero,
    (*),
    (+),
    (-),
    (==),
 )

-- this function takes commitment with point sets and returns only right MSM for further evaluation
-- as left MSM is equal to ONE * PI commitment
-- algorithm is ported from halo2 book
{-# INLINEABLE buildMSM #-}
buildMSM ::
    Scalar ->
    Scalar ->
    Scalar ->
    Scalar ->
    BuiltinBLS12_381_G1_Element ->
    BuiltinBLS12_381_G1_Element ->
    [Scalar] ->
    [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])] ->
    [[Scalar]] ->
    MSM
buildMSM x1 x2 x3 x4 f_comm pi_commitment proofX3QEvals commitmentMap pointSets = right
  where
    pointSetsIndexes :: [Integer]
    pointSetsIndexes = enumFromTo 0 (length pointSets - 1)

    -- x1Powers length can be precomputed
    -- todo length can be precomputed
    x1Powers :: [Scalar]
    x1Powers = powers (x1PowersCount pointSetsIndexes commitmentMap) x1

    (q_coms, q_eval_sets) = unzip (buildQ commitmentMap pointSetsIndexes x1Powers)

    -- todo length can be precomputed
    x4PowersCount = (max (length proofX3QEvals + 1) (length q_coms + 1))

    x4Powers :: [Scalar]
    x4Powers = powers x4PowersCount x4

    f_eval :: Scalar
    f_eval = evaluateLagrangePolynomials pointSets q_eval_sets x2 x3 proofX3QEvals

    final_com :: MSM
    final_com = finalCommitment q_coms f_comm x4Powers

    v :: Scalar
    v = computeV f_eval x4Powers proofX3QEvals

    right =
        appendTerm
            ( appendTerm
                final_com
                ( MSMElem
                    -- -vG1
                    (v, bls12_381_G1_neg (bls12_381_G1_uncompress bls12_381_G1_compressed_generator))
                )
            )
            ( MSMElem
                -- scaled pi
                (x3, pi_commitment)
            )

{-# INLINEABLE computeV #-}
computeV ::
    Scalar ->
    [Scalar] ->
    [Scalar] ->
    Scalar
computeV f_eval x4Powers proofX3QEvals =
    foldl
        (\acc (point, eval) -> acc + point * eval)
        (zero :: Scalar)
        (zip x4Powers (proofX3QEvals ++ [f_eval]))

{-# INLINEABLE finalCommitment #-}
-- todo this can be integrated into buildQ?
finalCommitment ::
    [MSM] ->
    BuiltinBLS12_381_G1_Element ->
    [Scalar] ->
    MSM
finalCommitment q_coms f_comm x4Powers =
    foldl
        (\accMSM (point, msm) -> addMSM accMSM (scaleMSM point msm))
        (MSM [])
        (zip x4Powers (q_coms ++ [MSM [MSMElem ((one :: Scalar), f_comm)]]))

{-# INLINEABLE evaluateLagrangePolynomials #-}
-- todo can not be precompute
evaluateLagrangePolynomials ::
    [[Scalar]] ->
    [[Scalar]] ->
    Scalar ->
    Scalar ->
    [Scalar] ->
    Scalar
evaluateLagrangePolynomials pointSets q_eval_sets x2 x3 proofX3QEvals =
    foldl
        ( \accEval ((points, evals), proofQEval) ->
            let
                rEval = lagrangeEvaluation (zip points evals) x3
                den = foldl (\acc point -> acc * (x3 - point)) one points
                eval = (proofQEval - rEval) * (recip den)
             in
                accEval * x2 + eval
        )
        zero
        (reverse (zip (zip pointSets q_eval_sets) proofX3QEvals))

{-# INLINEABLE x1PowersCount #-}
x1PowersCount :: [Integer] -> [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])] -> Integer
x1PowersCount pointSetsIndexes commitmentMap =
    foldl
        max
        0
        ( map
            ( \idx ->
                length
                    ( filter
                        (\(_, set_index, _, _) -> set_index == idx)
                        commitmentMap
                    )
            )
            pointSetsIndexes
        )

{-# INLINEABLE buildQ #-}
buildQ ::
    [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])] ->
    [Integer] ->
    [Scalar] ->
    [(MSM, [Scalar])]
buildQ commitmentMap pointSetsIndexes x1Powers =
    map
        ( \current_set_index ->
            let
                -- all commitments for given index
                -- todo precomputed
                commitmentsForIndex :: [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])]
                commitmentsForIndex =
                    filter (\(_, set_index, _, _) -> set_index == current_set_index) commitmentMap

                -- calculate inner products for commitments
                -- todo precomputed
                comm =
                    foldl
                        (\msm (x1Power, (c, _, _, _)) -> appendTerm msm (MSMElem (x1Power, c)))
                        (MSM [])
                        (zip x1Powers commitmentsForIndex)

                -- calculate inner product for evaluations
                -- todo can not be precomputed
                eval_set =
                    foldl
                        ( \acc (x1Power, (_, _, _, es)) ->
                            let
                                scaled = map (* x1Power) es
                             in
                                case acc of
                                    [] -> scaled
                                    accumulated -> map (\(a, b) -> a + b) (zip accumulated scaled)
                        )
                        []
                        (zip x1Powers commitmentsForIndex)
             in
                (comm, eval_set)
        )
        pointSetsIndexes
