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
        [ Tasty.testCase "interpolation for (1,1) eval at 1" existingPoint
        , Tasty.testCase "interpolation for (1,1) (2,2) eval at 4" linearCase
        , Tasty.testCase "interpolation for 2 points provided, eval at 42" biggerNumber
        , Tasty.testCase "interpolation for 4 points provided, eval at 42" nonLinearCase
        ]

existingPoint :: Tasty.Assertion
existingPoint = do
    let
        x1 = mkScalar 1
        y1 = mkScalar 1
        x = mkScalar 2
        expected = mkScalar 1
        result = lagrangeInPlace [(x1, y1)] x
    result @?= expected

linearCase :: Tasty.Assertion
linearCase = do
    let
        x1 = mkScalar 1
        y1 = mkScalar 1

        x2 = mkScalar 2
        y2 = mkScalar 2

        x = mkScalar 4
        expected = mkScalar 4
        result = lagrangeInPlace [(x1, y1), (x2, y2)] x
    result @?= expected

biggerNumber :: Tasty.Assertion
biggerNumber = do
    let
        x1 = mkScalar 3476578436
        y1 = mkScalar 676324645

        x2 = mkScalar 676324645
        y2 = mkScalar 32465456672

        x = mkScalar 42
        expected = mkScalar 0x3a7293683d1b89a083804afca51b323fa62924d60f0a40d3e46e6bc5d17ca858
        result = lagrangeInPlace [(x1, y1), (x2, y2)] x
    result @?= expected


nonLinearCase :: Tasty.Assertion
nonLinearCase = do
     let
         x1 = mkScalar 6763246453476578436
         y1 = mkScalar 2465456672435897394

         x2 = mkScalar 3476578436676324645
         y2 = mkScalar 3589739432465456672

         x3 = mkScalar 8796067088957874756
         y3 = mkScalar 3623657456997093465

         x4 = mkScalar 9686764663489690657
         y4 = mkScalar 7957456354576897947

         x = mkScalar 42
         expected = mkScalar 0x3afdcbe845065bf92428e7d4f1b41856674f05fa9d1c73234cb15a8c1fc43663

         result = lagrangeInPlace [(x1, y1), (x2, y2), (x3, y3), (x4, y4)] x
         unorderedResult =  lagrangeInPlace [(x3, y3), (x1, y1), (x4, y4), (x2, y2)] x

     unorderedResult @?= expected
     result @?= expected
