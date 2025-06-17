{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:no-inline-constants #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:remove-trace #-}

module Generic.VerifyCompiled (
    verifyAppliedCompiled,
    proofMintingPolicyContractApplied,
    writeToFile,
) where

import Data.ByteString as BS
import Flat (flat)
import Generic.Proof (sampleProof)
import Plutus.Crypto.BlsTypes (Scalar)
import Plutus.Crypto.Halo2.Generic.Verifier (verify)
import PlutusCore.Version (plcVersion110)
import PlutusTx
import qualified PlutusTx.Maybe as PlutusTx
import qualified PlutusTx.Prelude as PlutusTx
import UntypedPlutusCore (UnrestrictedProgram (UnrestrictedProgram))

verifyAdapter :: BuiltinData -> ()
verifyAdapter proofAsData =
    let PlutusTx.Just (proof, p1, p2, p3) = PlutusTx.fromBuiltinData proofAsData
        (result, _) = verify proof p1 p2 p3
     in if result PlutusTx.== PlutusTx.True
            then ()
            else PlutusTx.error ()

verifyCompiled :: CompiledCode (BuiltinData -> ())
verifyCompiled = $$(PlutusTx.compile [||verifyAdapter||])

sampleProofCompiled :: Scalar -> Scalar -> Scalar -> CompiledCode BuiltinData
sampleProofCompiled p1 p2 p3 =
    let proof = PlutusTx.toBuiltinData (sampleProof, p1, p2, p3)
     in proof `seq` PlutusTx.liftCode plcVersion110 proof

verifyAppliedCompiled :: Scalar -> Scalar -> Scalar -> CompiledCode ()
verifyAppliedCompiled p1 p2 p3 =
    case verifyCompiled `applyCode` sampleProofCompiled p1 p2 p3 of
        Left e -> error $ show e
        Right applied -> applied

writeToFile :: Scalar -> Scalar -> Scalar -> IO ()
writeToFile p1 p2 p3 =
    BS.writeFile "VerifierScript.flat" . flat . UnrestrictedProgram <$> PlutusTx.getPlcNoAnn $
        (proofMintingPolicyContractApplied p1 p2 p3)

-- proofMintingPolicyContractApplied

-- | we are only minting here. Burning will come later
{-# INLINEABLE proofMintingContract #-}
proofMintingContract :: BuiltinData -> Bool
proofMintingContract proof =
    let PlutusTx.Just (proof', p1, p2, p3) = PlutusTx.fromBuiltinData proof
        (result, _) = verify proof' p1 p2 p3
     in result PlutusTx.== PlutusTx.True

proofMintingPolicyContractApplied p1 p2 p3 =
    case $$(PlutusTx.compile [||PlutusTx.check . proofMintingContract||])
        `applyCode` (sampleProofCompiled p1 p2 p3) of
        Left e -> error $ show e
        Right applied -> applied
