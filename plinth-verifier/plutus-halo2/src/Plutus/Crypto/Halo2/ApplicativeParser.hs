{-# LANGUAGE TupleSections #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Plutus.Crypto.Halo2.ApplicativeParser (
    readPoint,
    readScalar,
    commonScalar,
    squeezeChallenge,
    Parser (runParser),
    State,
    run,
    fmap,
    pure,
    return,
    (<*>),
    (<$>),
    (>>=),
)
where

import Plutus.Crypto.BlsTypes (Scalar)
import qualified Plutus.Crypto.Halo2.Proof as Proof
import qualified Plutus.Crypto.Halo2.Transcript as Transcript
import PlutusTx.Prelude (
    Applicative (pure, (<*>)),
    BuiltinBLS12_381_G1_Element,
    Functor (fmap),
    emptyByteString,
    ($),
    (<$>),
 )

type State = (Proof.Proof, Transcript.Transcript)

newtype Parser a = Parser {runParser :: State -> (a, State)}

{-# INLINE run #-}
run :: Scalar -> Parser a -> Proof.Proof -> (a, State)
run transcriptRepr (Parser f) proof = f (proof, Transcript.addScalarToTranscript emptyByteString transcriptRepr)

{-# INLINE readPoint #-}
readPoint :: Parser BuiltinBLS12_381_G1_Element
readPoint = Parser $ \(proof, transcript) ->
    let (point, proof') = Proof.readPoint proof
        transcript' = Transcript.addPointToTranscript transcript point
     in (point, (proof', transcript'))

{-# INLINE readScalar #-}
readScalar :: Parser Scalar
readScalar = Parser $ \(proof, transcript) ->
    let (scalar, proof') = Proof.readScalar proof
        transcript' = Transcript.addScalarToTranscript transcript scalar
     in (scalar, (proof', transcript'))

{-# INLINE squeezeChallenge #-}
squeezeChallenge :: Parser Scalar
squeezeChallenge = Parser $ \(proof, transcript) ->
    let (scalar, transcript') = Transcript.squeezeChallenge transcript
     in (scalar, (proof, transcript'))

-- handle public inputs
{-# INLINE commonScalar #-}
commonScalar :: Scalar -> Parser Scalar
commonScalar scalar = Parser $ \(proof, transcript) ->
    let transcript' = Transcript.addCommonScalarToTranscript transcript scalar
     in (scalar, (proof, transcript'))

instance Functor Parser where
    {-# INLINE fmap #-}
    fmap f (Parser ma) =
        Parser $ \proof ->
            let (a, proof') = ma proof
             in (f a, proof')

instance Applicative Parser where
    {-# INLINE pure #-}
    pure a = Parser (a,)

    {-# INLINE (<*>) #-}
    (Parser mf) <*> (Parser ma) =
        Parser $ \proof ->
            let (f, proof') = mf proof
                (a, proof'') = ma proof'
             in (f a, proof'')

{-# INLINE (>>=) #-}
(>>=) :: Parser a -> (a -> Parser b) -> Parser b
(>>=) (Parser ma) f =
    Parser $ \proof ->
        let (a, proof') = ma proof
            Parser mb = f a
         in mb proof'

{-# INLINE return #-}
return :: a -> Parser a
return = pure
