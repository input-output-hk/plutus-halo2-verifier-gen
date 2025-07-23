{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Benchmarks (runBenchmarks) where

import qualified Data.Text as T
import Plutus.Crypto.Halo2 (
    Scalar,
    mkScalar,
 )
import Plutus.Crypto.Halo2.Halo2MultiOpenMSM (
    buildQ,
    computeV,
    evaluateLagrangePolynomials,
 )
import Plutus.Crypto.Halo2.LagrangePolynomialEvaluation (
    basis,
    lagrangeEvaluation,
 )
import PlutusTx (
    CompiledCode,
    compile,
    liftCodeDef,
    unsafeApplyCode,
 )
import PlutusTx.Test (
    EvalResult,
    displayEvalResult,
    evaluateCompiledCode,
 )
import ProofData
import qualified Test.Tasty as Tasty
import qualified Test.Tasty.HUnit as Tasty

runBenchmarks :: Tasty.TestTree
runBenchmarks =
    Tasty.testGroup
        "benchmarks to test how much CPU / MEM is used on Cardano"
        [ Tasty.testCase "checks how much resources is used for basis calculations" basisCalculation
        , Tasty.testCase "checks how much resources is used for full lagrange calculations" lagrangeCalculation
        , Tasty.testCase "checks how much resources is used for scalar V calculations" vCalculation
        , Tasty.testCase "checks how much resources is used for Q polynomials data" qCalculations
        , Tasty.testCase "checks how much resources is used for interpolating and evaluating lagrange polynomials" lagrangePolynomialsCalculations
        ]

basisCalculation :: Tasty.Assertion
basisCalculation = do
    let
        a = mkScalar 9686764663489690657
        b = mkScalar 9686764663489690657
        compiledCode :: CompiledCode (Scalar -> Scalar -> [(Scalar, Scalar)] -> Scalar)
        compiledCode = $$(compile [||basis||])
        result :: EvalResult
        result =
            evaluateCompiledCode
                ( compiledCode
                    `unsafeApplyCode` liftCodeDef a
                    `unsafeApplyCode` liftCodeDef b
                    `unsafeApplyCode` liftCodeDef [(a, b), (a, b), (a, b)]
                )
    logResult result
    ignoreAssertion

lagrangeCalculation :: Tasty.Assertion
lagrangeCalculation = do
    let
        ax = mkScalar 67632464534765784366763246453476578436
        ay = mkScalar 24654566724358973942465456672435897394

        bx = mkScalar 34765784366763246453476578436676324645
        by = mkScalar 35897394324654566723589739432465456672

        cx = mkScalar 87960670889578747568796067088957874756
        cy = mkScalar 36236574569970934653623657456997093465

        dx = mkScalar 96867646634896906579686764663489690657
        dy = mkScalar 79574563545768979477957456354576897947

        x = mkScalar 96867646634896906579686764663489690657231

        compiledCode :: CompiledCode ([(Scalar, Scalar)] -> Scalar -> Scalar)
        compiledCode = $$(compile [||lagrangeEvaluation||])
        result :: EvalResult
        result =
            evaluateCompiledCode
                ( compiledCode
                    `unsafeApplyCode` liftCodeDef [(ax, ay), (bx, by), (cx, cy), (dx, dy)]
                    `unsafeApplyCode` liftCodeDef x
                )
    logResult result
    ignoreAssertion

vCalculation :: Tasty.Assertion
vCalculation = do
    let
        compiledCode = $$(compile [||computeV||])
        result =
            evaluateCompiledCode
                ( compiledCode
                    `unsafeApplyCode` liftCodeDef f_eval
                    `unsafeApplyCode` liftCodeDef x4Powers
                    `unsafeApplyCode` liftCodeDef proofX3QEvals
                )
    logResult result
    ignoreAssertion

qCalculations :: Tasty.Assertion
qCalculations = do
    let
        compiledCode = $$(compile [||buildQ||])
        result =
            evaluateCompiledCode
                ( compiledCode
                    `unsafeApplyCode` liftCodeDef commitmentMap
                    `unsafeApplyCode` liftCodeDef pointSetsIndexes
                    `unsafeApplyCode` liftCodeDef x1Powers
                )
    logResult result
    ignoreAssertion

lagrangePolynomialsCalculations :: Tasty.Assertion
lagrangePolynomialsCalculations = do
    let
        compiledCode = $$(compile [||evaluateLagrangePolynomials||])
        result =
            evaluateCompiledCode
                ( compiledCode
                    `unsafeApplyCode` liftCodeDef pointSets
                    `unsafeApplyCode` liftCodeDef q_eval_sets
                    `unsafeApplyCode` liftCodeDef x2
                    `unsafeApplyCode` liftCodeDef x3
                    `unsafeApplyCode` liftCodeDef proofX3QEvals
                )
    logResult result
    ignoreAssertion

logResult :: EvalResult -> IO ()
logResult result = putStr . T.unpack $ displayEvalResult result

ignoreAssertion :: Tasty.Assertion
ignoreAssertion = Tasty.assertBool "" True
