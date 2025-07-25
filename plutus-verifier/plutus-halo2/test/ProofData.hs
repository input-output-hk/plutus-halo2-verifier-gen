{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoImplicitPrelude #-}

module ProofData where

import Data.Bifunctor (
    bimap,
 )
import Plutus.Crypto.BlsUtils (
    powers,
 )
import Plutus.Crypto.Halo2 (
    Scalar,
    compressG1Point,
    mkFp,
    mkScalar,
 )
import Plutus.Crypto.Halo2.Halo2MultiOpenMSM (
    buildQ,
    computeV,
    evaluateLagrangePolynomials,
 )
import Plutus.Crypto.Halo2.MSMTypes (MSM)
import PlutusTx.List (
    unzip,
 )
import PlutusTx.Prelude (
    BuiltinBLS12_381_G1_Element,
    Integer,
    (.),
 )

x_current :: Scalar
x_current = mkScalar 0x65e2000f8ef4d864b59536948015f6d968e559ecaccae4d58aea34b54593652d
x_next :: Scalar
x_next = mkScalar 0x31519ba428b9a878713c8271fddc7c6b865263177e914929e191ddcf6b5322ab
x_last :: Scalar
x_last = mkScalar 0x3ec5492f557134eff7dc7496381d4b4e7201406b26f739bd34fcf882cfcbafe8

a1 :: BuiltinBLS12_381_G1_Element
a1 =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x1248ab31621cfaac32f093c051c410a09744dd0faef7fa25671d6f4274932c62f1d72ca31eeec56c07d54e3df4b322e7
        , 0x16e7a9acff1f58eaa2cbc7bd316331d6073240b8f712bd7d400b1107a5b69db6d0b139939eddf7371222ba347a6904ce
        )

a2 :: BuiltinBLS12_381_G1_Element
a2 =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x159ed03170f4ac2ea7bedf73c64142024d7b1fa4fcd0d4e408215a0bde731d4d43ea8aa30a94d702dd13a63179a47b46
        , 0x9e2b5a5f941a0f6a72354d66f6988a92ba9ff28395ae947cfd6f1b81eb1aa97ce68cdc62294c7018fb5834b99543c05
        )

adviceEval1 :: Scalar
adviceEval1 = mkScalar 0x5f76010b62cf6059d7808b466e1da1ba4343a539510bcbd01cb917f7c480a86
adviceEval2 :: Scalar
adviceEval2 = mkScalar 0x4f734d5aebf9745ff96600052940240e31dd1dab47f3aa956d9035ecf365891
adviceEval3 :: Scalar
adviceEval3 = mkScalar 0x1e22146e243252e9abcf8b0b6c04e66c11aded7e51514fecaabef5f072d0ebe4

permutations_committed_a :: BuiltinBLS12_381_G1_Element
permutations_committed_a =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x17848d5311d369df05a761e23b25c90b3b810ee7d85fe5ed46aefa037bfdfdaaede878552f24842fc6a31b1d70df8f07
        , 0x195813d83297eea3baeca37f552f9b2148d9dfc45d49049683854a9fbb083970b9465ec9e1a7f77873fb57ad9027077d
        )
permutations_committed_b :: BuiltinBLS12_381_G1_Element
permutations_committed_b =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x195879f9a52d481b6c2700016eb4d13b4147bd494d31f373b8b21ad7ffb7db5e719a6ab4b74e45c4b64aa87553a7ccf4
        , 0x25ab32ac53b66ea6b9a1de563339c6f43bee5f1840b363d41bfe9b26075e8d1ae0b6191135db910af07e91c1f1e4296
        )
permutations_committed_c :: BuiltinBLS12_381_G1_Element
permutations_committed_c =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x211b5a2ee6cebcb79849e4d9bc5c6b87a645a1651a28ce0f9db347f12008af6f3928398d4e66bb4c7e567644bff848a
        , 0x171782ce3e24fd5118edb28d66ec00c8a2e6663b8d7a4f5c7b2a6fd51bf16675851a6a1e939d23d3e495167b289b1ee3
        )

permutations_evaluated_a_1 :: Scalar
permutations_evaluated_a_1 = mkScalar 0x397f7bb40249675fa320870e883c16aa4c9db701b32116abae732e0782241125
permutations_evaluated_a_2 :: Scalar
permutations_evaluated_a_2 = mkScalar 0x17fdce7661786e936a34e5c7bbedd9ed31ef0bffebb17f31eb36508527174411
permutations_evaluated_a_3 :: Scalar
permutations_evaluated_a_3 = mkScalar 0x5248e83b0e250badfd5053e081755fde61b756a693949f353b5e4fe1fd705311
permutations_evaluated_b_1 :: Scalar
permutations_evaluated_b_1 = mkScalar 0x203c13675c678e7c9a4f4a689e35d28010cb150c95595376faa7017c8784ee1
permutations_evaluated_b_2 :: Scalar
permutations_evaluated_b_2 = mkScalar 0x624209f64c929e840b04dac276c2b69b2a9ad40c9823133802496a679fe31443
permutations_evaluated_b_3 :: Scalar
permutations_evaluated_b_3 = mkScalar 0x4e43688f42c777271622c91cbf0e2b15532c17d6dfbb78d0a571977bdf044ad0
permutations_evaluated_c_1 :: Scalar
permutations_evaluated_c_1 = mkScalar 0x590899f51b74fdac2d3c259a40af8852af78be746e14afca8b976f56d51113ec
permutations_evaluated_c_2 :: Scalar
permutations_evaluated_c_2 = mkScalar 0x5c38c73499577e22eacd430d10455ac8790cae69124ad586cb407133417870c3

f1_commitment :: BuiltinBLS12_381_G1_Element
f1_commitment =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x0270eb78970b53437b3a4276411cc0b7e6a8f2816ffa4d9123f36cb222756a1dc606a6c4272cfc50be36b6fde6f64bd6
        , 0x0a230c41985f9802305fd769a848faca2201732cd96a3a64ce223d9280ebb8d591bc0d2b1fe9b4bb59c797037c95df50
        )
f2_commitment :: BuiltinBLS12_381_G1_Element
f2_commitment =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x0c57d93657619448d98a8ca9eebdd49d64a6116985f19cc85807eaa8c21eccabd314c8fa94296cd441e0f765d735df6d
        , 0x08580868d4d9add3351b1b19f1b47dbc7c02a09cae38233c716dce0fe26371985474ce033c73bccfeeaa8325bfa87d58
        )

p1_commitment :: BuiltinBLS12_381_G1_Element
p1_commitment =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x194a9f8c7be9b3ba3ed8d41f987d5e8d8e82762c1fd60ed2c867b525a2ef65afbbee65cb414d7a1284455fdf9e08e0ca
        , 0x123476c5cffc91ccadd05977098b4073a7aeee164a0a4a2b906474b90e921c064b7f5beca5307334afc5c02749af12da
        )
p2_commitment :: BuiltinBLS12_381_G1_Element
p2_commitment =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x0e904120fccb366638cc5407f4b3e2679f584798886a1dcef969443711b6708a545ea4a5b8babc1965134ba2c6a96fcf
        , 0x0b56013d2411fe9009a122eff44e2c6ab09a49e847a3e97391ea84acd86005c60c282e91e7dcdda4a7622432f0a24720
        )
p3_commitment :: BuiltinBLS12_381_G1_Element
p3_commitment =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x1743eab7fd58cb7dd924f9e6a446334ef1b2a0925284da9e8ff26159555eb33477738b502137e2c8aa6cc96c82a05fb8
        , 0x0365ec18ccedf38050d61398c35022fda2b656b1267bb15019567038cd39878e4d18bf0308ef0d003ab68d05b9e676fc
        )

fixedEval1 :: Scalar
fixedEval1 = mkScalar 0x376a75777caea8ea9d776fd83bc8d7d7f9b2aa53a485b0ff160cb439c2f755b4
fixedEval2 :: Scalar
fixedEval2 = mkScalar 0x476f6aad615e73ff1bfca152045102309b9ed1d43bed76e965395f1c54fccd4c

permutationCommon1 :: Scalar
permutationCommon1 = mkScalar 0x50c1bf37ea85b1271d85cc7dee9a4c91ee3c0e1e7b2c3e44cb02393044615f25
permutationCommon2 :: Scalar
permutationCommon2 = mkScalar 0x672f699c694c09ca38ceb6127a14a553699638fa25b353000783e52399649244
permutationCommon3 :: Scalar
permutationCommon3 = mkScalar 0x3485cc141ec1fd83be58d673b02b4d09e4c0890e58696f6711c7b271062bb9ce

vanishingRand :: BuiltinBLS12_381_G1_Element
vanishingRand =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x11ed947d0c22c55430e39be31033df0ed216861ff8b52ed01cb98045e5951b4937d14ae7921a67f502a6d2c0d5bb20a7
        , 0x184b1cff3fffc6e33072c2db3d983db7443a5ad59b18ee8385631b6dc6ffd2cd033da6cc5fa3f88ae9ef33da27accea8
        )
randomEval :: Scalar
randomEval = mkScalar 0xd8dd522568fa8f86fb21333ab3fccfe394db46481718cae33b04ce239f3952f

vanishing_g :: BuiltinBLS12_381_G1_Element
vanishing_g =
    (compressG1Point . bimap mkFp mkFp)
        ( 0x17e9428ff130e86b8586d1f6e95083f9c41a7f751946b76cbfa8eb9b4e2b78976c555b302fae0d8d2f366c7bfc5b760e
        , 0x13c9d5a1b494b3b5bcf4b79f2ea6835bcf865f0034636d91a94e09abe766ec5562d25a86add1bedd106c770026a29520
        )
vanishing_s :: Scalar
vanishing_s = mkScalar 0x2d37f683c04f39c20845ae6195816cd8ce96b3b6d155b7a04e4f32f60b74878a

x1 :: Scalar
x1 = mkScalar 0x25dbe380cca31996adfe0536275c9fe0e70f4c00c87bfe2df90d6dcbd9c6c643
x2 :: Scalar
x2 = mkScalar 0x453fe79d8e3a830d417882a1403b735fe5150db8de91c8277e4bca08eb8c9830

x3 :: Scalar
x3 = mkScalar 0x6c180a84842b308c78d360330b43eb74047473918589c83ff05e2971b82a7025
q_eval_on_x3_1 :: Scalar
q_eval_on_x3_1 = mkScalar 0x339ae4e8dce696d1014ffe1ab23e138050721064733801ee2adcab1a315e5807
q_eval_on_x3_2 :: Scalar
q_eval_on_x3_2 = mkScalar 0x39c6df152113d0f905fbd3441b5f3c50855c91eb1013cbf720ce5b139da83ab0
q_eval_on_x3_3 :: Scalar
q_eval_on_x3_3 = mkScalar 0x2fdc1d3df4b9639b7993a91a1be1f179f7f328e552ac03e9d241e8c60bf1f8fd
x4 :: Scalar
x4 = mkScalar 0x4a458f7c6a72c5efa4756daf7379ed4dd6e676306741a3bf08e3061eda88ab0f

-- example point sets with correct order of sets in list
pointSets :: [[Scalar]]
pointSets = [[x_current, x_next], [x_current], [x_current, x_next, x_last]]

pointSetsIndexes :: [Integer]
pointSetsIndexes = [0 .. 2]

-- example commitment map, tuples are (commitment, point_set_index, points, evaluations)
commitmentMap :: [(BuiltinBLS12_381_G1_Element, Integer, [Scalar], [Scalar])]
commitmentMap =
    [ (a1, 0, [x_current, x_next], [adviceEval1, adviceEval3])
    , (a2, 1, [x_current], [adviceEval2])
    , (permutations_committed_a, 2, [x_current, x_next, x_last], [permutations_evaluated_a_1, permutations_evaluated_a_2, permutations_evaluated_a_3])
    , (permutations_committed_b, 2, [x_current, x_next, x_last], [permutations_evaluated_b_1, permutations_evaluated_b_2, permutations_evaluated_b_3])
    , (permutations_committed_c, 0, [x_current, x_next], [permutations_evaluated_c_1, permutations_evaluated_c_2])
    , (f1_commitment, 1, [x_current], [fixedEval1])
    , (f2_commitment, 1, [x_current], [fixedEval2])
    , (p1_commitment, 1, [x_current], [permutationCommon1])
    , (p2_commitment, 1, [x_current], [permutationCommon2])
    , (p3_commitment, 1, [x_current], [permutationCommon3])
    , (vanishing_g, 1, [x_current], [vanishing_s])
    , (vanishingRand, 1, [x_current], [randomEval])
    ]

-- evaluation of parts from buildMSM
proofX3QEvals :: [Scalar]
proofX3QEvals = [q_eval_on_x3_1, q_eval_on_x3_2, q_eval_on_x3_3]

x1Powers :: [Scalar]
x1Powers = powers 8 x1

(q_coms :: [MSM], q_eval_sets :: [[Scalar]]) = unzip (buildQ commitmentMap pointSetsIndexes x1Powers)

x4Powers :: [Scalar]
x4Powers = powers 4 x4

f_eval :: Scalar
f_eval = evaluateLagrangePolynomials pointSets q_eval_sets x2 x3 proofX3QEvals

v :: Scalar
v = computeV f_eval x4Powers proofX3QEvals
