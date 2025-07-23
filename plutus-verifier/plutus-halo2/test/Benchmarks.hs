{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Benchmarks (runBenchmarks) where

import Control.Concurrent
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
        -- first polynomial
        p1_ax = mkScalar 0x65e2000f8ef4d864b59536948015f6d968e559ecaccae4d58aea34b54593652d
        p1_ay = mkScalar 0x1155cdbca5d1b7322d3fc79c28bea909a58db052c68a6905e63cdf1180a7e77a

        p1_bx = mkScalar 0x31519ba428b9a878713c8271fddc7c6b865263177e914929e191ddcf6b5322ab
        p1_by = mkScalar 0x739fcc72d0e2cdc04c6b6f1c49794a5e14a1b1a0c09ed2429a38a2d50c46ac80

        -- second polynomial
        p2_ax = mkScalar 0x65e2000f8ef4d864b59536948015f6d968e559ecaccae4d58aea34b54593652d
        p2_ay = mkScalar 0x488de24ae86e68664ac32e8d2360391791b8c60fef972c070fcd169411816bf5

        -- third polynomial
        p3_ax = mkScalar 0x65e2000f8ef4d864b59536948015f6d968e559ecaccae4d58aea34b54593652d
        p3_ay = mkScalar 0x403dd8f400926f35ca81b49a16bf39125bd5055a45859a65f87d36cd8d3f1bf5

        p3_bx = mkScalar 0x31519ba428b9a878713c8271fddc7c6b865263177e914929e191ddcf6b5322ab
        p3_by = mkScalar 0x4d5929f64321f54286e7c88200c1bcc9dafeada8320f28276210a4c531c9ea9f

        p3_cx = mkScalar 0x3ec5492f557134eff7dc7496381d4b4e7201406b26f739bd34fcf882cfcbafe8
        p3_cy = mkScalar 0x452f3a5bfd621ecf05b14659a3f6ee668efc8a994c6ffea0f9427672848f4c1a

        p1 = [(p1_ax, p1_ay), (p1_bx, p1_by)]
        p2 = [(p2_ax, p2_ay)]
        p3 = [(p3_ax, p3_ay), (p3_bx, p3_by), (p3_cx, p3_cy)]

        compiledCodeP1 :: CompiledCode ([(Scalar, Scalar)] -> Scalar -> Scalar)
        compiledCodeP1 = $$(compile [||lagrangeEvaluation||])
        resultP1 :: EvalResult
        resultP1 =
            evaluateCompiledCode
                ( compiledCodeP1
                    `unsafeApplyCode` liftCodeDef p1
                    `unsafeApplyCode` liftCodeDef x3
                )

        compiledCodeP2 :: CompiledCode ([(Scalar, Scalar)] -> Scalar -> Scalar)
        compiledCodeP2 = $$(compile [||lagrangeEvaluation||])
        resultP2 :: EvalResult
        resultP2 =
            evaluateCompiledCode
                ( compiledCodeP2
                    `unsafeApplyCode` liftCodeDef p2
                    `unsafeApplyCode` liftCodeDef x3
                )

        compiledCodeP3 :: CompiledCode ([(Scalar, Scalar)] -> Scalar -> Scalar)
        compiledCodeP3 = $$(compile [||lagrangeEvaluation||])
        resultP3 :: EvalResult
        resultP3 =
            evaluateCompiledCode
                ( compiledCodeP3
                    `unsafeApplyCode` liftCodeDef p3
                    `unsafeApplyCode` liftCodeDef x3
                )
    threadDelay 1000000
    putStrLn ""
    putStrLn "\n complexity for 1st set"
    logResult resultP1
    putStrLn "\n complexity for 2nd set"
    logResult resultP2
    putStrLn "\n complexity for 3rd set"
    logResult resultP3
    putStrLn ""
    threadDelay 1000000

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
    threadDelay 1000000
    putStrLn ""
    putStrLn "pointSets"
    putStrLn $ show pointSets
    putStrLn "q_eval_sets"
    putStrLn $ show q_eval_sets
    putStrLn "x2"
    putStrLn $ show x2
    putStrLn "x3"
    putStrLn $ show x3
    putStrLn "proofX3QEvals"
    putStrLn $ show proofX3QEvals
    putStrLn ""
    threadDelay 1000000
    logResult result
    ignoreAssertion

logResult :: EvalResult -> IO ()
logResult result = putStr . T.unpack $ displayEvalResult result

ignoreAssertion :: Tasty.Assertion
ignoreAssertion = Tasty.assertBool "" True
