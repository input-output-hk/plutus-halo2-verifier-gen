module Lagrange (test) where

import Plutus.Crypto.Halo2 (
    mkScalar,
 )
import Plutus.Crypto.Halo2.LagrangePolynomialEvaluation (lagrangeInPlace)
import qualified Test.Tasty as Tasty
import Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as Tasty

test :: Tasty.TestTree
test =
    Tasty.testGroup
        "unit tests"
        [ Tasty.testCase "interpolation for (1,1) eval at 1" proofTest
        , Tasty.testCase "interpolation for (1,1) (2,2) eval at 4" proofTest1
        , Tasty.testCase "interpolation for (3476578436,435897394) (676324645,32465456672) eval at 42" proofTest1
        ]

proofTest :: Tasty.Assertion
proofTest = do
    let
        x1 = mkScalar 1
        y1 = mkScalar 1
        x = mkScalar 2
        expected = mkScalar 1
        result = lagrangeInPlace [(x1, y1)] x
    result @?= expected

proofTest1 :: Tasty.Assertion
proofTest1 = do
    let
        x1 = mkScalar 1
        y1 = mkScalar 1
        x2 = mkScalar 2
        y2 = mkScalar 2
        x = mkScalar 4
        expected = mkScalar 4
        result = lagrangeInPlace [(x1, y1), (x2, y2)] x
    result @?= expected

proofTest2 :: Tasty.Assertion
proofTest2 = do
    let
        x1 = mkScalar 3476578436
        y1 = mkScalar 676324645
        x2 = mkScalar 676324645
        y2 = mkScalar 32465456672
        x = mkScalar 42
        expected = mkScalar 50005543427641638138774391874998187797399605664044700965529451695707093553735
        result = lagrangeInPlace [(x1, y1), (x2, y2)] x
    result @?= expected
