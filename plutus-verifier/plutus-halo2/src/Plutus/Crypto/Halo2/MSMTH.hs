{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

module Plutus.Crypto.Halo2.MSMTH (
    buildMSMTH,
    NameAnn (NameAnn),
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
import qualified PlutusTx.Builtins as PlutusTx
import qualified PlutusTx.Prelude as PlutusTx

{-# INLINEABLE buildMSMElem #-}
buildMSMElem :: Scalar -> Scalar -> MinimalVerifierQuery -> MSMElem
buildMSMElem powerOfV powerOfU query = MSMElem (powerOfV PlutusTx.* powerOfU, mv_commitment query)

{-# INLINEABLE buildMSMScalar #-}
buildMSMScalar :: Scalar -> MinimalVerifierQuery -> Scalar
buildMSMScalar powerOfV query = powerOfV PlutusTx.* mv_eval query

{-
NameAnn is a helper data type that is supposed
to be used by TH code only. It should not be
used in compiled Plutus script.

`Name` is a name of `MinimalVerifierQuery` binding
`a` is a label used to declare the rotation for the query

For generic verifier `a` should be replaced with a label
that carries the exact information about rotation.
Then `rotated` argument for `buildMSMTH` can be removed
and code for rotatiations of `x * w^i` can be generated
inside of `buildMSMTH`
-}
data NameAnn a = NameAnn a Name

-- this function corresponds to loop:
-- https://github.com/input-output-hk/plutus-halo2-verifier/blob/925c3d9cd4f214ad11e3f59c8762c95456d8fa11/halo2-test/src/main.rs#L765
squashQueries :: (Eq a) => [NameAnn a] -> [[Name]]
squashQueries = map (reverse . snd) . reverse . toList . foldl fold Seq.Empty
  where
    fold accum (NameAnn idx name) =
        let pred' = (== idx) . fst
            update = second (name :)
         in case Seq.findIndexL pred' accum of
                Just index ->
                    let toUpdate = Seq.index accum index
                     in Seq.update index (update toUpdate) accum
                Nothing -> (idx, [name]) Seq.<| accum

newtype QueryName = QueryName Name
newtype UName = UName Name
newtype VName = VName Name

expand :: [(a, [b])] -> [(a, b)]
expand [] = []
expand ((a, bs) : r) = ((a,) <$> bs) ++ expand r

buildMSMTH :: (Eq a) => Name -> Name -> [NameAnn a] -> [Name] -> [Name] -> Q Exp
buildMSMTH v u queries ws rotated = do
    when (null queries) $ fail "Empty queries list"

    let squashed = squashQueries queries
        maxLength = length squashed
        maxNestedLength = maximum $ fmap length squashed

    (vNames, vDecls) <- unzip <$> genScalarPowerDecls "v" v maxNestedLength
    (uNames, uDecls) <- unzip <$> genScalarPowerDecls "u" u maxLength

    let zipped :: [(UName, [(VName, QueryName)])] =
            coerce $ zip uNames $ zip vNames <$> squashed

    (finalMSMName, finalMSMDecl) <- genFinalMSM zipped
    (finalEvalName, finalEvalDecl) <- genFinalEval zipped
    (finalWitnessesName, finalWitnessesDecl) <- genFinalWitnesses uNames ws
    (finalWitnessesAuxName, finalWitnessesAuxDecl) <- genFinalWitnessesAux rotated uNames ws

    let decls =
            vDecls
                ++ uDecls
                ++ [ finalMSMDecl
                   , finalEvalDecl
                   , finalWitnessesDecl
                   , finalWitnessesAuxDecl
                   ]

    let rightSide =
            [|
                $(varE finalWitnessesAuxName)
                    `addMSM` $(varE finalMSMName)
                    `appendTerm` MSMElem
                        ( $(varE finalEvalName)
                        , PlutusTx.bls12_381_G1_neg
                            (PlutusTx.bls12_381_G1_uncompress PlutusTx.bls12_381_G1_compressed_generator)
                        )
                |]

    LetE decls <$> [|($(varE finalWitnessesName), $(rightSide))|]

genFinalWitnessesAux :: [Name] -> [Name] -> [Name] -> Q (Name, Dec)
genFinalWitnessesAux rotated uNames ws = do
    finalWitnessesAuxName <- newName "finalWitnessesAux"
    finalWitnessesAuxExp <- genFinalWitnessesAuxExp
    pure
        ( finalWitnessesAuxName
        , ValD
            (BangP $ VarP finalWitnessesAuxName)
            (NormalB finalWitnessesAuxExp)
            []
        )
  where
    genFinalWitnessesAuxExp = do
        --      rotated corresponds to Z element in original rust code
        --      when calculating
        --      witness_with_aux.append_term(power_of_u * z, wi.into());
        --      points are always rotations of x used in queries
        l <- forM (zip3 rotated uNames ws) $
            \(x, u, w) ->
                [|MSMElem ($(varE u) PlutusTx.* $(varE x), $(varE w))|]
        [|MSM $(pure $ ListE l)|]

genFinalWitnesses :: [Name] -> [Name] -> Q (Name, Dec)
genFinalWitnesses uNames ws = do
    finalWitnessesName <- newName "finalWitnesses"
    finalWitnessesExp <- genFinalWitnessesExp
    pure
        ( finalWitnessesName
        , ValD
            (BangP $ VarP finalWitnessesName)
            (NormalB finalWitnessesExp)
            []
        )
  where
    genFinalWitnessesExp = do
        l <- forM (zip uNames ws) $
            \(u, w) ->
                [|MSMElem ($(varE u), $(varE w))|]
        [|MSM $(pure $ ListE l)|]

genFinalEval :: [(UName, [(VName, QueryName)])] -> Q (Name, Dec)
genFinalEval zipped = do
    finalEvalName <- newName "finalEval"
    finalEvalExp <- genFinalEvalExp
    pure
        ( finalEvalName
        , ValD
            (BangP $ VarP finalEvalName)
            (NormalB finalEvalExp)
            []
        )
  where
    genFinalEvalExp = foldl foldOuter [|mkScalar 0|] zipped

    foldOuter accum (UName uName, l) =
        [|$(accum) PlutusTx.+ $(varE uName) PlutusTx.* $(handleInner l)|]

    handleInner = foldl foldInner [|mkScalar 0|]

    foldInner accum (VName vName, QueryName queryName) =
        [|$(accum) PlutusTx.+ buildMSMScalar $(varE vName) $(varE queryName)|]

genFinalMSM :: [(UName, [(VName, QueryName)])] -> Q (Name, Dec)
genFinalMSM zipped = do
    finalMSMName <- newName "finalMSM"
    finalMSMExp <- genFinalMSMExp
    pure
        ( finalMSMName
        , ValD
            (BangP $ VarP finalMSMName)
            (NormalB finalMSMExp)
            []
        )
  where
    genFinalMSMExp = do
        l <- forM (expand zipped) $
            \(UName u, (VName v, QueryName query)) ->
                [|buildMSMElem $(varE v) $(varE u) $(varE query)|]
        [|MSM $(pure $ ListE l)|]

genScalarPowerDecls :: String -> Name -> Int -> Q [(Name, Dec)]
genScalarPowerDecls prefix v num = do
    v0Name <- newName prefix
    v0Exp <- [|mkScalar 1|]
    let v0Decl =
            ValD
                (BangP $ VarP v0Name)
                (NormalB v0Exp)
                []
    fmap ((v0Name, v0Decl) :) (go v0Name (num - 1))
  where
    go :: Name -> Int -> Q [(Name, Dec)]
    go prevVName num'
        | num' == 0 = pure []
        | otherwise = do
            vNextName <- newName prefix
            uNextExp <- [|$(varE prevVName) PlutusTx.* $(varE v)|]
            let vNextDecl =
                    ValD
                        (BangP $ VarP vNextName)
                        (NormalB uNextExp)
                        []
            fmap ((vNextName, vNextDecl) :) (go vNextName (num' - 1))
