module Main where

import qualified Benchmarks
import qualified Generic.VerificationTestHaskell
import qualified Generic.VerificationTestPlutus
import Generic.VerifyCompiled (writeToFile)
import qualified Halo2MultiOpenMSM
import qualified Lagrange
import Test.Tasty (defaultMain, testGroup)

import EvalUtils (
    parsedInputs,
 )
import Plutus.Crypto.Halo2 (
    bls12_381_field_prime,
    mkScalar,
 )
import PlutusTx.Prelude (
    modulo,
 )

main :: IO ()
main = do
    let p1 =
            mkScalar
                ((parsedInputs !! 0) `modulo` bls12_381_field_prime)
    let p2 =
            mkScalar
                ((parsedInputs !! 1) `modulo` bls12_381_field_prime)
    let p3 =
            mkScalar
                ((parsedInputs !! 2) `modulo` bls12_381_field_prime)

    --  this saves compiled plutus UPLC to a file for use with plutus analytics tools
    Generic.VerifyCompiled.writeToFile p1 p2 p3

    defaultMain $
        testGroup
            "Haskell and Plutus Halo2 tests"
            [ Generic.VerificationTestHaskell.test
            , Generic.VerificationTestPlutus.test
            , Lagrange.test
            , Halo2MultiOpenMSM.test
            , Benchmarks.runBenchmarks
            ]
