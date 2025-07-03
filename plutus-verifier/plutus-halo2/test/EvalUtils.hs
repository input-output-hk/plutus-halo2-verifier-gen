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

publicInputs :: Data.ByteString.ByteString
publicInputs = $(embedFile "test/Generic/serialized_public_input.hex")

parsedInputs :: [Integer]
parsedInputs = map parseFile (Data.ByteString.Char8.lines publicInputs)

parseFile :: Data.ByteString.ByteString -> Integer
parseFile line = case Numeric.readHex (Data.ByteString.Char8.unpack line) of
    [(n, "")] -> n
    _ -> Prelude.error "failed to load public inputs from proof_data/public_inputs.hex"
