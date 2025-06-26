{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

module Plutus.Crypto.Halo2.MultiopenMSM (
--    buildMSMTH,

) where

import Control.Monad (forM, when)
import Data.Bifunctor (second)
import Data.Coerce (coerce)
import Data.Foldable (toList)
import qualified Data.Sequence as Seq
import Language.Haskell.TH (varE)
import Language.Haskell.TH.Syntax (
    Body (NormalB),
    Dec (ValD),
    Exp (LetE, ListE),
    Name,
    Pat (BangP, VarP),
    Q,
    Quote (newName),
 )
import Plutus.Crypto.BlsTypes (Scalar, mkScalar)
import Plutus.Crypto.Halo2.MSMTypes (
    MSMElem (MSMElem),
    MinimalVerifierQuery (mv_commitment, mv_eval),
 )
import qualified PlutusTx.AssocMap as Map
import qualified PlutusTx.BuiltinList as BIList
import PlutusTx.Builtins (BuiltinArray, listToArray)
import qualified PlutusTx.Builtins as PlutusTx
import PlutusTx.List (findIndex)
import qualified PlutusTx.Prelude as PlutusTx

data Rotation = Previous | Current | Next | Last

instance PlutusTx.Eq Rotation where
    {-# INLINEABLE (==) #-}
    Previous == Previous = True
    Current == Current = True
    Next == Next = True
    Last == Last = True
    _ == _ = False

data Query = Query
    { getPoint :: Rotation
    , getCommitment :: PlutusTx.BuiltinBLS12_381_G1_Element
    , getEvaluation :: Scalar
    }

data CommitmentData = CommitmentData
    { getCm :: PlutusTx.BuiltinBLS12_381_G1_Element
    , getPointIndices :: [Int]
    , getEvaluations :: [Scalar]
    }
    deriving (Show, Eq)

type IntermediateSets = ([CommitmentData], [[Rotation]])

data ProcessingError = DuplicatedQuery
    deriving (Show)

{-# INLINEABLE constructIntermediateSets #-}
constructIntermediateSets :: [Query] -> [Rotation] -> IntermediateSets
constructIntermediateSets queries points_ordered =
    let
        point_index_map = Map.safeFromList ((zip [0 ..] points_ordered) :: [(Integer, Rotation)])
        index_point_map = Map.safeFromList ((zip points_ordered [0 ..]) :: [(Rotation, Integer)])
        commitmentMapWithReverseValues =
            foldl
                ( \acc query ->
                    let
                        c = getCommitment query
                        p = getPoint query
                        point_index = findIndex (PlutusTx.== p) points_ordered

                        value = case (Map.lookup c acc) of
                            Nothing -> [point_index]
                            Just old_value -> point_index : old_value
                     in
                        Map.insert c value acc
                )
                Map.empty
                queries
        commitmentMap = Map.mapWithKey (\k e -> reverse e) commitmentMap


     in
        ([], [])
