{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.MultiOpenMSM (buildMSM, buildQ, computeV, evaluateLagrange, finalCommitment) where

import Plutus.Crypto.BlsTypes (
    Scalar,
    recip,
 )
import Plutus.Crypto.BlsUtils (
    powers,
 )
import Plutus.Crypto.Halo2.LagrangePolynomialEvaluation (
    lagrangeInPlace,
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
    find,
    foldl,
    head,
    length,
    map,
    replicate,
    reverse,
    unzip,
    zip,
    (++),
 )
import PlutusTx.Prelude (
    Bool (False, True),
    Integer,
    bls12_381_G1_compressed_generator,
    bls12_381_G1_neg,
    bls12_381_G1_uncompress,
    enumFromTo,
    one,
    zero,
    (*),
    (+),
    (-),
    (==),
 )

-- this function takes commitment with point sets and returns only right MSM for further evaluation
-- as left MSM is equal to ONE * PI commitment
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

    -- todo estimate, instead of using 15
    -- this has to be equal the length of longest commitment set associated with a set index
    x1Powers :: [Scalar]
    x1Powers = powers 15 x1
    -- length of this is max ( proofX3QEvals_len + 1 , q_coms_len + 1 )
    x4Powers :: [Scalar]
    x4Powers = powers 15 x4

    (q_coms, q_eval_sets) = unzip (buildQ commitmentMap pointSetsIndexes x1Powers)

    f_eval :: Scalar
    f_eval = evaluateLagrange pointSets q_eval_sets x2 x3 proofX3QEvals

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

{-# INLINEABLE evaluateLagrange #-}
evaluateLagrange ::
    [[Scalar]] ->
    [[Scalar]] ->
    Scalar ->
    Scalar ->
    [Scalar] ->
    Scalar
evaluateLagrange pointSets q_eval_sets x2 x3 proofX3QEvals =
    foldl
        ( \accEval ((points, evals), proofQEval) ->
            let
                rEval = lagrangeInPlace (zip points evals) x3
                den = foldl (\acc point -> acc * (x3 - point)) one points
                eval = (proofQEval - rEval) * (recip den)
             in
                accEval * x2 + eval
        )
        zero
        (reverse (zip (zip pointSets q_eval_sets) proofX3QEvals))

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
                commitmentsForIndex :: [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])]
                commitmentsForIndex =
                    filter
                        ( \c -> case c of
                            (_, set_index, _, _) | set_index == current_set_index -> True
                            _ -> False
                        )
                        commitmentMap

                -- calculate inner products for commitments
                comm =
                    foldl
                        (\msm (x1Power, (c, _, _, _)) -> appendTerm msm (MSMElem (x1Power, c)))
                        (MSM [])
                        (zip x1Powers commitmentsForIndex)

                -- calculate inner product for evaluations
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
