{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# HLINT ignore "Use camelCase" #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

module Generic.VerificationTestHaskell (test, verify) where

import Control.Concurrent
import Data.Tree (flatten)
import EvalUtils (
    parsedInputs,
 )
import Generic.Proof (sampleProof)
import Plutus.Crypto.Halo2 (
    bls12_381_field_prime,
    compressG1Point,
    mkFp,
    mkScalar,
 )
import Plutus.Crypto.Halo2.Generic.Verifier (verify)
import PlutusTx.Prelude (
    Bool (False, True),
    modulo,
 )
import System.IO (hPutStrLn, stderr)
import qualified Test.Tasty as Tasty
import Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as Tasty
import Prelude (fmap, map, mapM_, print, pure, putStrLn, sequence, show, (!!), (++))

-- this test runs verifier code in haskell, without compiling it to UPLC to find out if there are any logical bugs
-- unrelated to UPLC, the same logic is executed in VerificationTestPlutus but after compiling it to UPLC

test :: Tasty.TestTree
test =
    Tasty.testGroup
        "unit tests"
        [Tasty.testCase "proof verification test in haskell" proofTest]

-- Tasty.assertEqual "Extraction via parser failed"
proofTest :: Tasty.Assertion
proofTest = do
    let
        p1 =
            mkScalar
                ((parsedInputs !! 0) `modulo` bls12_381_field_prime)
        p2 =
            mkScalar
                ((parsedInputs !! 1) `modulo` bls12_381_field_prime)
        p3 =
            mkScalar
                ((parsedInputs !! 2) `modulo` bls12_381_field_prime)

        (final_verification, traces) = verify sampleProof p1 p2 p3
    -- makes debug data yellow and easy to spot
    threadDelay 1000000
    putStrLn "\n"
    mapM_ (\s -> putStrLn ("\ESC[33m" ++ show s ++ "\n")) traces
    putStrLn "\n"
    threadDelay 1000000
    final_verification @?= True
