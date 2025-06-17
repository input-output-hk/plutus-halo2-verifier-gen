{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module Generic.Proof where

import Data.Aeson as Aeson
import Data.ByteString as BS
import Data.FileEmbed (embedFile)

import Data.Maybe (fromMaybe)
import Plutus.Crypto.Halo2 (Proof)
import PlutusTx.Prelude (toBuiltin)

sampleProof :: Proof
sampleProof =
    let content = $(embedFile "test/Generic/serialized_proof.json")
        asBuiltin = toBuiltin . BS.pack <$> Aeson.decodeStrict content
        err = "Not a serialized proof"
     in fromMaybe (error err) asBuiltin
