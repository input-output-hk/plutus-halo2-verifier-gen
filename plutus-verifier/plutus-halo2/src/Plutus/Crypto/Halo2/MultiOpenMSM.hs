{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.MultiOpenMSM where

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
    unzip,
    zip,
    (++),
 )
import PlutusTx.Prelude (
    Bool (False, True),
    Integer,
    one,
    zero,
    (*),
    (+),
    (-),
 )

-- this function takes commitment with point sets and returns left and right MSM for further evaluation
{-# INLINEABLE buildMSM #-}
buildMSM ::
    Scalar ->
    Scalar ->
    Scalar ->
    Scalar ->
    BuiltinBLS12_381_G1_Element ->
    [Scalar] ->
    [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])] ->
    [[Scalar]] ->
    (MSM, MSM)
buildMSM x1 x2 x3 x4 f_comm proofX3QEvals commitmentMap pointSets = (MSM [], MSM [])
  where
    pointSetsIndexes :: [Integer]
    pointSetsIndexes = [0 .. (length pointSets - 1)]

    x1Powers :: [Scalar]
    x1Powers = x1 : [x1 * x | x <- x1Powers]

    x4Powers :: [Scalar]
    x4Powers = x4 : [x4 * x | x <- x1Powers]

    result =
        map
            ( \set_index ->
                let
                    -- all commitments for given index
                    commitmentsForIndex :: [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])]
                    commitmentsForIndex =
                        filter
                            ( \c -> case c of
                                (_, set_index, _, _) -> True
                                _ -> False
                            )
                            commitmentMap

                    -- calculate inner products for commitments and for evaluations
                    comm =
                        foldl
                            (\msm (x1Power, (c, _, _, _)) -> appendTerm msm (MSMElem (x1Power, c)))
                            (MSM [])
                            (zip x1Powers commitmentsForIndex)

                    eval_set =
                        -- this multiply all elements from evaluation list es and sums up result
                        map
                            ( \(x1Power, (_, _, _, es)) ->
                                foldl
                                    ( \acc evaluation ->
                                        acc + evaluation * x1Power
                                    )
                                    (zero :: Scalar)
                                    es
                            )
                            (zip x1Powers commitmentsForIndex)
                 in
                    (comm, eval_set)
            )
            pointSetsIndexes
    (q_coms, q_eval_sets) = unzip result

    f_eval =
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
            (zip (zip pointSets q_eval_sets) proofX3QEvals)

    final_com =
        foldl
            (\accMSM (x4Power, msm) -> addMSM accMSM (scaleMSM x4Power msm))
            (MSM [])
            (zip x4Powers (q_coms ++ [MSM [MSMElem ((one :: Scalar), f_comm)]]))
