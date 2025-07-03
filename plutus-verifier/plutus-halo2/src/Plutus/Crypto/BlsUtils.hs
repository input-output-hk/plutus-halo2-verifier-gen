{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.BlsUtils (powers, rotateOmega, Tracing, traceG1, traceG2, traceScalar, traceMVQ, traceMSM) where

import Plutus.Crypto.BlsTypes (
    Scalar,
    mkScalar,
    powMod,
    unFp,
    unScalar,
 )
import Plutus.Crypto.Halo2.CompressUncompress (
    unCompressG1Point,
 )
import Plutus.Crypto.Halo2.MSMTypes
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
 )
import PlutusTx.Prelude (
    BuiltinByteString,
    Integer,
    abs,
    bls12_381_G2_compress,
    fromBuiltin,
    otherwise,
    (*),
    (-),
    (<),
    (==),
 )
import Text.Hex (encodeHex)
import Text.Printf (printf)
import qualified Prelude as Haskell

printAsHex :: BuiltinByteString -> Haskell.String
printAsHex a = (Haskell.show Haskell.. encodeHex Haskell.. fromBuiltin Haskell.$ a)

{-# INLINEABLE powers #-}
powers :: Integer -> Scalar -> [Scalar]
powers num base = go (mkScalar 1) num
  where
    go :: Scalar -> Integer -> [Scalar]
    go first num' =
        if num' == 0
            then []
            else first : go (base * first) (num' - 1)

{-# INLINEABLE rotateOmega #-}
rotateOmega :: Scalar -> Scalar -> Scalar -> Integer -> Scalar
rotateOmega omega omegaInv value rotation
    | rotation < 0 =
        value * powMod omegaInv (abs rotation)
    | otherwise =
        value * powMod omega rotation

data Tracing = TracingMSM MSM | TracingScalar Scalar | TracingG1 BuiltinBLS12_381_G1_Element | TracingG2 BuiltinBLS12_381_G2_Element | TracingMVQ MinimalVerifierQuery Scalar deriving (Haskell.Eq)

traceG1 :: BuiltinBLS12_381_G1_Element -> Tracing
traceG1 = TracingG1

traceG2 :: BuiltinBLS12_381_G2_Element -> Tracing
traceG2 = TracingG2

traceScalar :: Scalar -> Tracing
traceScalar = TracingScalar

traceMVQ :: MinimalVerifierQuery -> Scalar -> Tracing
traceMVQ = TracingMVQ

traceMSM :: MSM -> Tracing
traceMSM = TracingMSM

instance Haskell.Show Tracing where
    -- show :: Tomato -> Haskell.String
    show (TracingScalar t) = printf "0x%x" (unScalar t)
    show (TracingG1 t) =
        let
            (x, y) = unCompressG1Point t
            x_s = unFp x
            y_s = unFp y
         in
            printf "( 0x%x , 0x%x )" x_s y_s
    show (TracingG2 t) =
        let compressed_form = bls12_381_G2_compress t
         in printf (printAsHex compressed_form)
    show (TracingMVQ (MinimalVerifierQuery commitment eval) rotation) =
        let
            c = Haskell.show (TracingG1 commitment)
            e = Haskell.show (TracingScalar eval)
            p = Haskell.show (TracingScalar rotation)
         in
            "( commitment: " Haskell.++ c Haskell.++ ", point: " Haskell.++ p Haskell.++ ", evaluation: " Haskell.++ e Haskell.++ " )"
    show (TracingMSM (MSM es)) =
        let formatted =
                Haskell.map
                    ( \(MSMElem (scalar, g1)) ->
                        "( "
                            Haskell.++ (printf "0x%x" (unScalar scalar))
                            Haskell.++ "; "
                            Haskell.++ (Haskell.show (TracingG1 g1))
                            Haskell.++ ")"
                    )
                    es
         in Haskell.show formatted
