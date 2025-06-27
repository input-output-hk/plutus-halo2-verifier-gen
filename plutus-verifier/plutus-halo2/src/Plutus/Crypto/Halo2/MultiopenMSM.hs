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
import qualified Data.Set as Set
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
import PlutusTx.List (findIndex, nubBy, sortBy)
import qualified PlutusTx.Prelude as PlutusTx

data RotationOfX = Previous | Current | Next | Last
    deriving (Ord, Eq)

instance PlutusTx.Eq RotationOfX where
    {-# INLINEABLE (==) #-}
    Previous == Previous = True
    Current == Current = True
    Next == Next = True
    Last == Last = True
    _ == _ = False

data Query = Query
    { getPoint :: RotationOfX
    , getCommitment :: PlutusTx.BuiltinBLS12_381_G1_Element
    , getEvaluation :: Scalar
    }

data CommitmentData = CommitmentData
    { get_Commitment :: PlutusTx.BuiltinBLS12_381_G1_Element
    -- index of a set of points that is related to commitment from get_Commitment
    , getSetIndex :: Int
    -- those 2 lists have to be in sync
    , getPointIndices :: [RotationOfX]
    , getEvaluations :: [Scalar]
    }
    deriving (Show, Eq)


type IntermediateSets = ([CommitmentData], [[RotationOfX]])

data ProcessingError = DuplicatedQuery
    deriving (Show)

-- I do not have to calculate Rotations ordering as it is calculated when code is generated and it is provided in correct order
-- because of that I can just declare point_index_map and index_point_map instead of calculating them
{-# INLINEABLE constructIntermediateSets #-}
constructIntermediateSets :: [Query] -> [RotationOfX] -> IntermediateSets
constructIntermediateSets queries points_ordered =
    let
        point_index_map = Map.safeFromList ((zip [0 ..] points_ordered) :: [(Integer, RotationOfX)])
        index_point_map = Map.safeFromList ((zip points_ordered [0 ..]) :: [(RotationOfX, Integer)])
        -- zip with integers to get ordering information that is not present for keys in a map
        commitmentMapWithReverseValues =
            foldl
                ( \acc (commitment_index, query) ->
                    let
                        c = getCommitment query
                        p = getPoint query

                        value = case ((Map.lookup c acc), (Map.lookup p index_point_map)) of
                            -- first element of the list is indicating ordering of the commitments
                            (Nothing, Just point_index) -> point_index : [commitment_index]
                            (Just old_value, Just point_index) -> point_index : old_value
                     in
                        Map.insert c value acc
                )
                Map.empty
                (zip [0 ..] queries)
        -- first element in list that is value of this map is index used for stable ordering of commitment
        commitmentMap = Map.mapWithKey (\k e -> reverse e) commitmentMapWithReverseValues
        -- map from a commitment to set of points (rotations of point x) used for given commitment
        -- with integer used for preserving original order of commitments
        commitmentSetMap :: Map.Map PlutusTx.BuiltinBLS12_381_G1_Element (Integer, Set.Set Integer)
        commitmentSetMap =
            Map.mapWithKey
                ( \commitment points ->
                    -- tail points as first element is used for preserving the original order of commitments
                    (head points, Set.fromList (tail points :: [Integer]))
                )
                commitmentMap
        uniquePointSets :: [(Integer, Set.Set Integer)]
        uniquePointSets = nubBy (\(idx_a, _) (idx_b, _) -> idx_a == idx_b) (Map.elems commitmentSetMap)
        -- replace ordering numbers with actual indexes
        orderedPointSets = (sortBy (\(a, _) (b, _) -> compare a b) uniquePointSets)
        indexedPointSets = map (\(idx, (_, e)) -> (idx,e)) (zip [0..] orderedPointSets)

        -- in the end I want to have a ordered list of points sets, in the same way as they are in indexedPointSets
        -- and a vector of CommitmentData,
     in
        ([], [])
