{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module EvalUtils (
    Error (FreeVariableError, EvaluationError),
    exBudgetCPUToInt,
    exBudgetMemoryToInt,
    evalWithBudget,
    evalWithBudget',
    estimateCompiledCodeSize,
    parsedInputs,
    committedInputs,
)
where

import Control.Lens (Bifunctor (bimap), traverseOf, (^.))
import Control.Monad.Except (runExceptT)
import Data.Coerce (coerce)
import Data.SatInt (fromSatInt)
import Data.Text (Text)
import PlutusCore (serialisedSize)
import qualified PlutusCore as PLC
import PlutusCore.Evaluation.Machine.ExBudget (
    ExBudget (exBudgetCPU, exBudgetMemory),
 )
import qualified PlutusCore.Evaluation.Machine.ExBudgetingDefaults as PLC
import PlutusCore.Evaluation.Machine.ExMemory (
    ExCPU (ExCPU),
    ExMemory (ExMemory),
 )
import PlutusLedgerApi.Common (serialiseCompiledCode)
import PlutusTx (
    CompiledCode,
    getPlcNoAnn,
 )
import qualified UntypedPlutusCore as UPLC
import UntypedPlutusCore.Evaluation.Machine.Cek (
    CekEvaluationException,
    logEmitter,
 )
import qualified UntypedPlutusCore.Evaluation.Machine.Cek as UPLC

import qualified Data.ByteString
import qualified Data.ByteString.Char8
import Data.FileEmbed (embedFile)
import qualified Numeric
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
 )
import Plutus.Crypto.Halo2 (
    bls12_381_field_prime,
    bls12_381_base_prime,
    mkScalar,
    Scalar,
    Fp,
    constructG1Point,
    mkFp,
 )
import PlutusTx.Prelude (
    modulo,
 )

data Error
    = FreeVariableError
    | EvaluationError (CekEvaluationException UPLC.Name UPLC.DefaultUni UPLC.DefaultFun) ExBudget
    deriving (Show)

exBudgetCPUToInt :: ExBudget -> Integer
exBudgetCPUToInt = fromSatInt . coerce . exBudgetCPU

exBudgetMemoryToInt :: ExBudget -> Integer
exBudgetMemoryToInt = fromSatInt . coerce . exBudgetMemory

evalWithBudget :: CompiledCode a -> Either Error (ExBudget, [Text])
evalWithBudget compiledCode =
    let programE =
            PLC.runQuote $
                runExceptT @PLC.FreeVariableError $
                    traverseOf UPLC.progTerm UPLC.unDeBruijnTerm $
                        getPlcNoAnn compiledCode
     in case programE of
            Left _ -> Left FreeVariableError
            Right program ->
                let (result, UPLC.TallyingSt _ budget, logs) =
                        UPLC.runCek
                            PLC.defaultCekParametersForTesting
                            UPLC.tallying
                            logEmitter
                            $ program ^. UPLC.progTerm
                 in bimap (`EvaluationError` budget) (const (budget, logs)) result

evalWithBudget' :: CompiledCode () -> Either Error (ExBudget, [Text])
evalWithBudget' = evalWithBudget

estimateCompiledCodeSize :: CompiledCode a -> Integer
estimateCompiledCodeSize = serialisedSize . serialiseCompiledCode

parseScalar :: Data.ByteString.ByteString -> Scalar
parseScalar line = case Numeric.readHex (Data.ByteString.Char8.unpack line) of
    [(n, "")] -> mkScalar (n `modulo` bls12_381_field_prime)
    _ -> Prelude.error "failed to load public inputs from proof_data/public_inputs.hex"

parsedInputs :: [Scalar]
parsedInputs =
    let file = $(embedFile "test/Generic/serialized_public_input.hex") in
    map parseScalar (Data.ByteString.Char8.lines file)

parseBase :: Data.ByteString.ByteString -> Fp
parseBase line = case Numeric.readHex (Data.ByteString.Char8.unpack line) of
    [(n, "")] -> mkFp (n `modulo` bls12_381_base_prime)
    _ -> Prelude.error "failed to load public inputs from proof_data/public_inputs.hex"

committedInputs :: BuiltinBLS12_381_G1_Element
committedInputs = 
    let file = $(embedFile "test/Generic/serialized_committed_input.hex") in
    let coords = map parseBase (Data.ByteString.Char8.lines file) in
    constructG1Point (head coords, coords !! 1)