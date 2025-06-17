{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NumericUnderscores #-}
{-# OPTIONS_GHC -fplugin PlutusTx.Plugin
       -fplugin-opt PlutusTx.Plugin:max-cse-iterations=4
       -fplugin-opt PlutusTx.Plugin:max-simplifier-iterations-pir=0
       -fplugin-opt PlutusTx.Plugin:max-simplifier-iterations-uplc=0
       -fplugin-opt PlutusTx.Plugin:max-cse-iterations=0
       -fplugin-opt PlutusTx.Plugin:no-inline-constants
       -fplugin-opt PlutusTx.Plugin:no-preserve-logging
       -fplugin-opt PlutusTx.Plugin:remove-trace
       -fplugin-opt PlutusTx.Plugin:target-version=1.1.0
       -fplugin-opt PlutusTx.Plugin:verbosity=0 #-}

module Generic.VerificationTestPlutus (test) where

import qualified Data.Aeson as Aeson
import EvalUtils (
    estimateCompiledCodeSize,
    evalWithBudget',
    exBudgetCPUToInt,
    exBudgetMemoryToInt,
    parsedInputs,
 )
import GHC.Generics (Generic)
import Generic.VerifyCompiled (proofMintingPolicyContractApplied, verifyAppliedCompiled)
import Plutus.Crypto.Halo2 (
    bls12_381_field_prime,
    compressG1Point,
    mkFp,
    mkScalar,
 )
import PlutusTx.Prelude (
    Bool (False, True),
    modulo,
 )
import qualified Test.Tasty as Tasty
import qualified Test.Tasty.HUnit as Tasty

-- this test runs verifier code in UPLC, this test is doing exactly the same check as VerificationTestHaskell but
-- cod that is executed is first compiled to UPLC

scriptSizeLimit :: Integer
scriptSizeLimit = 25_000

memoryLimit :: Integer
memoryLimit = 1_000_000_000_000_000 -- arbitrarily set, now huge

cpuLimit :: Integer
cpuLimit = 1_000_000_000_000_000 -- arbitrarily set, now huge

data BenchmarkResults = BenchmarkResults
    { scriptSize :: Integer
    , cpu :: Integer
    , mem :: Integer
    }
    deriving (Eq, Show, Generic)

instance Aeson.ToJSON BenchmarkResults

test :: Tasty.TestTree
test = Tasty.testCase "proof verification test in plutus + budget calculations" $ do
    let p1 =
            mkScalar
                ((parsedInputs !! 0) `modulo` bls12_381_field_prime)
    let p2 =
            mkScalar
                ((parsedInputs !! 1) `modulo` bls12_381_field_prime)
    let p3 =
            mkScalar
                ((parsedInputs !! 2) `modulo` bls12_381_field_prime)

    let scriptSize' = estimateCompiledCodeSize (proofMintingPolicyContractApplied p1 p2 p3)

    Tasty.assertBool
        ("Applied script is too big: " <> show scriptSize')
        (scriptSize' < scriptSizeLimit)

    case evalWithBudget' (verifyAppliedCompiled p1 p2 p3) of
        Left e -> fail $ "Evaluator failed: " <> show e
        Right (budget, traces) -> do
            putStrLn $ ""
            putStrLn $ "Resources used: " <> show budget
            putStrLn $ "Script size: " <> show scriptSize'

            Tasty.assertBool
                "Memory budget exceeded"
                (exBudgetMemoryToInt budget < memoryLimit)

            Tasty.assertBool
                "ExUnits budget exceeded"
                (exBudgetCPUToInt budget < cpuLimit)

            let results =
                    BenchmarkResults
                        scriptSize'
                        (exBudgetCPUToInt budget)
                        (exBudgetMemoryToInt budget)

            Aeson.encodeFile "benchmark.json" results
