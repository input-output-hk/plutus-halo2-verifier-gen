{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveLift #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Plutus.Crypto.BlsTypes (
    bls12_381_base_prime,
    Fp (..),
    mkFp,
    mkFp2,
    Fp2 (..),
    bls12_381_field_prime,
    Scalar,
    unScalar,
    mkScalar,
    MultiplicativeGroup (..),
    pow,
    powMod,
    modularExponentiationScalar,
    modularExponentiationFp,
    modularExponentiationFp2,
    powerOfTwoExponentiation,
    reverseByteString,
    one,
    Rotation (..),
) where

import qualified Language.Haskell.TH.Lift as TH
import PlutusTx (makeIsDataIndexed, makeLift)
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
    BuiltinByteString,
    bls12_381_G1_add,
    bls12_381_G1_compressed_zero,
    bls12_381_G1_neg,
    bls12_381_G1_scalarMul,
    bls12_381_G1_uncompress,
    bls12_381_G2_add,
    bls12_381_G2_compressed_zero,
    bls12_381_G2_neg,
    bls12_381_G2_scalarMul,
    bls12_381_G2_uncompress,
    consByteString,
    emptyByteString,
    indexByteString,
 )
import PlutusTx.Numeric (
    negate,
 )
import PlutusTx.Prelude (
    AdditiveGroup (..),
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Bool (..),
    Eq (..),
    Integer,
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
    Ord ((<), (<=)),
    compare,
    divide,
    dropByteString,
    error,
    even,
    modulo,
    otherwise,
    ($),
    (&&),
    (.),
    (/=),
    (<>),
    (>),
    (||),
 )
import Text.Printf (printf)
import qualified Prelude as Haskell

-- In this module, we setup the two prime order fields for BLS12-381.
-- as the type Fp (base points) and Scalar.
-- Note that for safety, both the Scalar and Fp constructors
-- are not exposed. Instead, the mkScalar and mkFp suffice,
-- which fail in a script if an integer provided that is negative.

-- The prime order of the generator in the field. So, g^order = id,
bls12_381_field_prime :: Integer
bls12_381_field_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513

-- The prime of the base field. So for a g on the curve, its
-- x and y coordinates are elements of the base field.
bls12_381_base_prime :: Integer
bls12_381_base_prime =
    4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

newtype Scalar = Scalar {sc :: Integer}
    deriving (Haskell.Eq, Haskell.Ord)
    deriving (TH.Lift)

{-# INLINEABLE unScalar #-}
unScalar s = (sc s) `modulo` bls12_381_field_prime

makeLift ''Scalar
makeIsDataIndexed ''Scalar [('Scalar, 0)]

instance Haskell.Show Scalar where
    show :: Scalar -> Haskell.String
    show = printf "0x%x" . unScalar

-- Exclude for safety negative integers and integers large/equal
-- to the field prime. This is the primary interface to work with
-- the Scalar type onchain. This is for security reasons
-- (to make sure they are field elements).
{-# INLINEABLE mkScalar #-}
mkScalar :: Integer -> Scalar
mkScalar n
    | 0 <= n && n < bls12_381_field_prime = Scalar n
    | otherwise = error ()

instance Eq Scalar where
    {-# INLINEABLE (==) #-}
    (==) :: Scalar -> Scalar -> Bool
    Scalar a == Scalar b = a == b

instance AdditiveSemigroup Scalar where
    {-# INLINEABLE (+) #-}
    (+) :: Scalar -> Scalar -> Scalar
    (+) (Scalar a) (Scalar b) = Scalar $ (a + b) `modulo` bls12_381_field_prime

instance AdditiveMonoid Scalar where
    {-# INLINEABLE zero #-}
    zero :: Scalar
    zero = Scalar 0

instance AdditiveGroup Scalar where
    {-# INLINEABLE (-) #-}
    (-) :: Scalar -> Scalar -> Scalar
    (-) (Scalar a) (Scalar b) = Scalar $ (a - b) `modulo` bls12_381_field_prime

instance MultiplicativeSemigroup Scalar where
    {-# INLINEABLE (*) #-}
    (*) :: Scalar -> Scalar -> Scalar
    (*) (Scalar a) (Scalar b) = Scalar $ (a * b) `modulo` bls12_381_field_prime

instance MultiplicativeMonoid Scalar where
    {-# INLINEABLE one #-}
    one :: Scalar
    one = Scalar 1

instance Ord Scalar where
    compare :: Scalar -> Scalar -> Haskell.Ordering
    (Scalar a) `compare` (Scalar b) = a `compare` b

-- In plutus 1.9, PlutusTx.Numeric does not implement a Multiplicative group.
-- But since we use a field, inversion is well-defined if we exclude 0.
-- We also implement the reciprocal (the multiplicative inverse of an element in the group).
-- For the additive group, there is negate function in PlutusTx.Numeric.
class (MultiplicativeMonoid a) => MultiplicativeGroup a where
    div :: a -> a -> a
    recip :: a -> a

-- Modular exponentiation by squaring. This assumes that the exponent is
-- a big endian bytestring. Note that integegerToByteString is little endian.
{-# INLINEABLE modularExponentiationScalar #-}
modularExponentiationScalar :: Scalar -> Integer -> Scalar
modularExponentiationScalar b e
    | e < 0 = zero
    | e == 0 = one
    | even e = modularExponentiationScalar (b * b) (e `divide` 2)
    | otherwise = b * modularExponentiationScalar (b * b) ((e - 1) `divide` 2)

-- Reverse a builtin byte string of arbitrary length
-- This can convert between little and big endian.
{-# INLINEABLE reverseByteString #-}
reverseByteString :: BuiltinByteString -> BuiltinByteString
reverseByteString bs
    | bs == emptyByteString = bs
    | otherwise =
        reverseByteString (dropByteString 1 bs) <> consByteString (indexByteString bs 0) emptyByteString

-- this one costs around 12.1% of cpu budget
-- while bitshifts modExp cost around 9.6%
{-# INLINEABLE powMod #-}
powMod :: Scalar -> Integer -> Scalar
powMod b e
    | e < 0 = zero
    | e == 0 = one
    | even e = powMod (b * b) (e `divide` 2)
    | otherwise = b * powMod (b * b) ((e - 1) `divide` 2)

-- In math this is b^a mod p, where b is of type scalar and a any integer
-- note that there is still some overhead here due to the conversion from
-- little endian to big endian (and bs <-> integer). This can be
-- optimized in the future.
instance Module Integer Scalar where
    {-# INLINEABLE scale #-}
    scale :: Integer -> Scalar -> Scalar
    scale a b = modularExponentiationScalar b a -- powMod b a is also a correct implementation

instance MultiplicativeGroup Scalar where
    {-# INLINEABLE div #-}
    div :: Scalar -> Scalar -> Scalar
    div a b
        | b == Scalar 0 = error ()
        | otherwise = a * recip b
    {-# INLINEABLE recip #-}
    recip :: Scalar -> Scalar
    recip (Scalar a) = Scalar (go a bls12_381_field_prime 1 0)
      where
        go !u !v !x1 !x2 =
            if u /= 1
                then
                    let !q = v `divide` u
                        r = v - q * u
                        x = x2 - q * x1
                     in go r u x x1
                else x1 `modulo` bls12_381_field_prime

-- This is a special case of modular exponentiation, where the exponent is a power of two.
-- This saves alot of script budget. Note that for x^e,  e = 2^k, and k is used below
{-# INLINEABLE powerOfTwoExponentiation #-}
powerOfTwoExponentiation :: Scalar -> Integer -> Scalar
powerOfTwoExponentiation x k = if k < 0 then error () else go x k
  where
    go x' k'
        | k' == 0 = x'
        | otherwise = powerOfTwoExponentiation (x' * x') (k' - 1)

-- The field elements are the x and y coordinates of the points on the curve.
newtype Fp = Fp {unFp :: Integer} deriving (Haskell.Show, Haskell.Eq)
makeLift ''Fp
makeIsDataIndexed ''Fp [('Fp, 0)]

{-# INLINEABLE mkFp #-}
mkFp :: Integer -> Fp
mkFp n
    | 0 <= n && n < bls12_381_base_prime = Fp n
    | otherwise = error ()

-- first argument is real, second argument is imaginary
{-# INLINEABLE mkFp2 #-}
mkFp2 :: Fp -> Fp -> Fp2
mkFp2 = Fp2

instance Eq Fp where
    {-# INLINEABLE (==) #-}
    (==) :: Fp -> Fp -> Bool
    Fp a == Fp b = a == b

instance AdditiveSemigroup Fp where
    {-# INLINEABLE (+) #-}
    (+) :: Fp -> Fp -> Fp
    (+) (Fp a) (Fp b) = Fp $ (a + b) `modulo` bls12_381_base_prime

instance AdditiveMonoid Fp where
    {-# INLINEABLE zero #-}
    zero :: Fp
    zero = Fp 0

instance AdditiveGroup Fp where
    {-# INLINEABLE (-) #-}
    (-) :: Fp -> Fp -> Fp
    (-) (Fp a) (Fp b) = Fp $ (a - b) `modulo` bls12_381_base_prime

instance MultiplicativeSemigroup Fp where
    {-# INLINEABLE (*) #-}
    (*) :: Fp -> Fp -> Fp
    (*) (Fp a) (Fp b) = Fp $ (a * b) `modulo` bls12_381_base_prime

instance MultiplicativeMonoid Fp where
    {-# INLINEABLE one #-}
    one :: Fp
    one = Fp 1

{-# INLINEABLE modularExponentiationFp #-}
modularExponentiationFp :: Fp -> Integer -> Fp
modularExponentiationFp b e
    | e < 0 = zero
    | e == 0 = one
    | even e = modularExponentiationFp (b * b) (e `divide` 2)
    | otherwise = b * modularExponentiationFp (b * b) ((e - 1) `divide` 2)

instance Module Integer Fp where
    {-# INLINEABLE scale #-}
    scale :: Integer -> Fp -> Fp
    scale a b = modularExponentiationFp b a

instance MultiplicativeGroup Fp where
    {-# INLINEABLE div #-}
    div :: Fp -> Fp -> Fp
    div a b
        | b == Fp 0 = error ()
        | otherwise = a * scale (bls12_381_base_prime - 2) b -- use Fermat little theorem
    {-# INLINEABLE recip #-}
    recip :: Fp -> Fp
    recip = div one

instance Ord Fp where
    {-# INLINEABLE (<) #-}
    (<) :: Fp -> Fp -> Bool
    Fp a < Fp b = a < b
    {-# INLINEABLE (<=) #-}
    (<=) :: Fp -> Fp -> Bool
    Fp a <= Fp b = a <= b
    {-# INLINEABLE (>) #-}
    (>) :: Fp -> Fp -> Bool
    Fp a > Fp b = a > b

-- {-# INLINABLE (>=) #-}
-- Fp a >= Fp b = a >= b

-- The field elements are the x and y coordinates of the points on the curve.
data Fp2 = Fp2
    { real :: Fp
    , imaginary :: Fp
    }
    deriving (Haskell.Show, Haskell.Eq)
makeLift ''Fp2
makeIsDataIndexed ''Fp2 [('Fp2, 0)]

instance Eq Fp2 where
    {-# INLINEABLE (==) #-}
    (==) :: Fp2 -> Fp2 -> Bool
    Fp2 x1 y1 == Fp2 x2 y2 = x1 == x2 && y1 == y2

instance AdditiveSemigroup Fp2 where
    {-# INLINEABLE (+) #-}
    (+) :: Fp2 -> Fp2 -> Fp2
    (+) (Fp2 a b) (Fp2 c d) = Fp2 (a + c) (b + d)

instance AdditiveMonoid Fp2 where
    {-# INLINEABLE zero #-}
    zero :: Fp2
    zero = Fp2 zero zero

instance AdditiveGroup Fp2 where
    {-# INLINEABLE (-) #-}
    (-) :: Fp2 -> Fp2 -> Fp2
    (-) (Fp2 a b) (Fp2 c d) = Fp2 (a - c) (b - d)

instance MultiplicativeSemigroup Fp2 where
    {-# INLINEABLE (*) #-}
    (*) :: Fp2 -> Fp2 -> Fp2
    (*) (Fp2 a b) (Fp2 c d) = Fp2 (a * c - b * d) (a * d + b * c)

instance MultiplicativeMonoid Fp2 where
    {-# INLINEABLE one #-}
    one :: Fp2
    one = Fp2 one zero

{-# INLINEABLE pow #-}
pow :: Integer -> Integer -> Integer
pow b e
    | e < 0 = zero
    | e == 0 = 1
    | even e = pow (b * b) (e `divide` 2)
    | otherwise = b * pow (b * b) ((e - 1) `divide` 2)

{-# INLINEABLE modularExponentiationFp2 #-}
modularExponentiationFp2 :: Fp2 -> Integer -> Fp2
modularExponentiationFp2 b e
    | e < 0 = zero
    | e == 0 = one
    | even e = modularExponentiationFp2 (b * b) (e `divide` 2)
    | otherwise = b * modularExponentiationFp2 (b * b) ((e - 1) `divide` 2)

instance Module Integer Fp2 where
    {-# INLINEABLE scale #-}
    scale :: Integer -> Fp2 -> Fp2
    scale a b = modularExponentiationFp2 b a

instance MultiplicativeGroup Fp2 where
    {-# INLINEABLE div #-}
    div :: Fp2 -> Fp2 -> Fp2
    div a b
        | b == zero = error ()
        | otherwise = a * recip b
    {-# INLINEABLE recip #-}
    recip :: Fp2 -> Fp2
    recip (Fp2 a b) = Fp2 (a `div` norm) (negate b `div` norm)
      where
        norm = a * a + b * b

instance Ord Fp2 where
    {-# INLINEABLE (<) #-}
    (<) :: Fp2 -> Fp2 -> Bool
    Fp2 a b < Fp2 c d = a < c || (a == c && b < d)
    {-# INLINEABLE (<=) #-}
    (<=) :: Fp2 -> Fp2 -> Bool
    Fp2 a b <= Fp2 c d = a <= c && b <= d
    {-# INLINEABLE (>) #-}
    (>) :: Fp2 -> Fp2 -> Bool
    Fp2 a b > Fp2 c d = a > c || (a == c && b > d)

-- {-# INLINABLE (>=) #-}
-- Fp2 a b >= Fp2 c d =

instance AdditiveSemigroup BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE (+) #-}
    (+) :: BuiltinBLS12_381_G1_Element -> BuiltinBLS12_381_G1_Element -> BuiltinBLS12_381_G1_Element
    (+) = bls12_381_G1_add

instance AdditiveMonoid BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE zero #-}
    zero :: BuiltinBLS12_381_G1_Element
    zero = bls12_381_G1_uncompress bls12_381_G1_compressed_zero

instance AdditiveGroup BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE (-) #-}
    (-) :: BuiltinBLS12_381_G1_Element -> BuiltinBLS12_381_G1_Element -> BuiltinBLS12_381_G1_Element
    (-) a b = a + bls12_381_G1_neg b

instance Module Scalar BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE scale #-}
    scale :: Scalar -> BuiltinBLS12_381_G1_Element -> BuiltinBLS12_381_G1_Element
    scale (Scalar a) = bls12_381_G1_scalarMul a

instance AdditiveSemigroup BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE (+) #-}
    (+) :: BuiltinBLS12_381_G2_Element -> BuiltinBLS12_381_G2_Element -> BuiltinBLS12_381_G2_Element
    (+) = bls12_381_G2_add

instance AdditiveMonoid BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE zero #-}
    zero :: BuiltinBLS12_381_G2_Element
    zero = bls12_381_G2_uncompress bls12_381_G2_compressed_zero

instance AdditiveGroup BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE (-) #-}
    (-) :: BuiltinBLS12_381_G2_Element -> BuiltinBLS12_381_G2_Element -> BuiltinBLS12_381_G2_Element
    (-) a b = a + bls12_381_G2_neg b

instance Module Scalar BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE scale #-}
    scale :: Scalar -> BuiltinBLS12_381_G2_Element -> BuiltinBLS12_381_G2_Element
    scale (Scalar a) = bls12_381_G2_scalarMul a

{- | Describes the relative rotation of a vector. Negative numbers represent
reverse (leftmost) rotations and positive numbers represent forward (rightmost)
rotations. Zero represents no rotation.
-}
newtype Rotation = Rotation {getRotation :: Integer} deriving (Haskell.Show)
