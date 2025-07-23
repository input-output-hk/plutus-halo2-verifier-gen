{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Halo2MultiOpenMSM (test) where

import Data.Bifunctor (
    bimap,
 )
import Plutus.Crypto.Halo2 (
    Scalar,
    compressG1Point,
    mkFp,
    mkScalar,
 )
import Plutus.Crypto.Halo2.Halo2MultiOpenMSM (
    buildQ,
    computeV,
    evaluateLagrangePolynomials,
 )
import PlutusTx.List (
    unzip,
 )
import PlutusTx.Prelude (
    BuiltinBLS12_381_G1_Element,
    Integer,
    one,
    (*),
    (.),
 )
import ProofData
import qualified Test.Tasty as Tasty
import Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as Tasty

test :: Tasty.TestTree
test =
    Tasty.testGroup
        "unit tests for MSM multi open"
        [ Tasty.testCase "check V correctness for test case" assertCorrectV
        , Tasty.testCase "check f evaluation correctness for test case" assertCorrectFEval
        , Tasty.testCase "check q evaluation sets correctness for test case" assertCorrectQEvalSets
        ]

-- values extracted from rust version of multi open for this case
expectedV :: Scalar
expectedV = mkScalar 0x2884628a888c5cb437fd6589734866cffa56ec5c7870979785fbdeb21f0380ec

expectedFEval :: Scalar
expectedFEval = mkScalar 0x68254f544250d7c2b9bbdf4998c6643ea7ba4cffce8f1269d1df571084424282

expectedQEvalSets :: [[Scalar]]
expectedQEvalSets =
    [
        [ mkScalar 0x1155cdbca5d1b7322d3fc79c28bea909a58db052c68a6905e63cdf1180a7e77a
        , mkScalar 0x739fcc72d0e2cdc04c6b6f1c49794a5e14a1b1a0c09ed2429a38a2d50c46ac80
        ]
    , [mkScalar 0x488de24ae86e68664ac32e8d2360391791b8c60fef972c070fcd169411816bf5]
    ,
        [ mkScalar 0x403dd8f400926f35ca81b49a16bf39125bd5055a45859a65f87d36cd8d3f1bf5
        , mkScalar 0x4d5929f64321f54286e7c88200c1bcc9dafeada8320f28276210a4c531c9ea9f
        , mkScalar 0x452f3a5bfd621ecf05b14659a3f6ee668efc8a994c6ffea0f9427672848f4c1a
        ]
    ]

assertCorrectV :: Tasty.Assertion
assertCorrectV = v @?= expectedV

assertCorrectFEval :: Tasty.Assertion
assertCorrectFEval = f_eval @?= expectedFEval

assertCorrectQEvalSets :: Tasty.Assertion
assertCorrectQEvalSets = q_eval_sets @?= expectedQEvalSets
