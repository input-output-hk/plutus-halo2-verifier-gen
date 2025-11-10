use aiken/builtin.{bls12_381_final_verify, bls12_381_miller_loop}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{
  add as addG1, generator as generatorG1, scale as scaleG1, sub as subG1,
}
use aiken/crypto/bls12_381/g2.{
  add as addG2, generator as generatorG2, scale as scaleG2, sub as subG2,
}
use aiken/crypto/bls12_381/scalar.{
  Scalar, add, field_prime as bls12_381_field_prime, from_int, mul, neg, sub,
  to_int,
}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use transcript.{
  common_scalar, construct_transcript, read_point, read_scalar,
  squeeze_challenge,
}

// inputs, equations and results are extracted from ATMS with lookups that is set up in examples/equations_test.rs
test gates_equations() {
  let evaluation_at_0 = from_int(0)
  let last_evaluation = from_int(0)
  let active_rows = from_int(0)

  let product_eval_1 = from_int(0)
  let product_next_eval_1 = from_int(0)

  let permuted_input_eval_1 = from_int(0)
  let permuted_input_inv_eval_1 = from_int(0)
  let permuted_table_eval_1 = from_int(0)

  let scalarZero = from_int(0)
  let scalarOne = from_int(1)

  let theta =
    from_int(0x48a17da0ce7885b53b609909665412512739401571ab20716244304db94b428f)
  let beta = from_int(1)
  let gamma = from_int(1)

  let advice_eval_1 =
    from_int(0x2adbf91251b4db148b220a521ac2a208ee75b53ac893ac2fbf369c2df26aeb7)
  let advice_eval_2 =
    from_int(0x40f4f14c27358575f7811cf8947279ae6d0247774fc4f55f78f3ff95b9b05288)
  let advice_eval_3 =
    from_int(0xa55fe86313a855488336dc7a6fd1b1aaa15f3b7fe595c949b4fc50af2d5519f)
  let advice_eval_4 =
    from_int(0x1056d65d58330b0dc99f3344e205974876396e8d3beb5a8ff369dc43a27c817b)
  let advice_eval_5 =
    from_int(0x596c729da70d11df208e780c187c9f92b2ae136ae5c035cdc88db1300f2851b9)
  let advice_eval_6 =
    from_int(0x3dfd79f8ad5aa3812b3e5a25f0adede82d6de0b37f94541b5a7e98eaf0106bf4)

  let advice_eval_8 =
    from_int(0x3c6bef5b745941d713423d8ad42b947cd60e355b4f5c733b4cd93cd6b5ad4193)
  let advice_eval_9 =
    from_int(0x79eba8060e0597be2afeb60ef1f7b8feeba30f9fd02c57235cc6a9e77272891)
  let advice_eval_10 =
    from_int(0x2837baa30f5f061f6742ddecf0ad0783f9e16815b3f0dc17eb520a702bb91891)
  let advice_eval_11 =
    from_int(0x457851bcc0fc8308acef1f8681f2039d5895350200b23bb7966768be24b271e8)

  let fixed_eval_1 =
    from_int(0x55928b88ddb296b0cb27cb9f2512db9d1a5ce2708b0421dca903a72200691774)
  let fixed_eval_2 =
    from_int(0x6e1a2c9fa4b502a0680b092827714a7de50833209b97f240de7432cff53768e3)
  let fixed_eval_3 =
    from_int(0xc1d45573ba7fefcf37741d95c9dad6c52bce5f2f1461c0b79831ecbd8995ec7)
  let fixed_eval_4 =
    from_int(0x2add66566e552b231bef08e94424344ca07400e91f4f51360278817f430857f4)
  let fixed_eval_5 =
    from_int(0x2d610cc6b0a63d1bc1e827715e94753df0d3018715ba7bd443b3ffcbf426c95f)
  let fixed_eval_6 =
    from_int(0x5f9db6d17c659db2cc421296047496044fe679f45eec63f2464cbbde29d120e7)
  let fixed_eval_7 =
    from_int(0x152fd5eadc1dbd89997d896a208f255e14ee436fd990bd803b932fc5474c823c)
  let fixed_eval_8 = from_int(0x0)
  let fixed_eval_9 =
    from_int(0xf11e53da736ba2217fe8eb0f4ee6ea180ae1343fe4ab720715fe949a6a2400)
  let fixed_eval_10 =
    from_int(0x6cdb9fe1cfaaf83a7874e9fe7a9124008735a03a54165e2704fb1bfc9ad7fdc0)
  let fixed_eval_11 =
    from_int(0x143a74155111cf71e255bc42cf7ea10f14b4c9c51c8eb3d61734e9e7df748c35)
  let fixed_eval_12 =
    from_int(0x2c675385c9ebc777a0d209b504967291cce5cb36b355e6c54459cadc26ffc9ea)
  let fixed_eval_13 =
    from_int(0x6b723f8bc3e096e8b0257c6e53f1071c0d21a438325f8c6aa21ef2e934b79a7f)
  let fixed_eval_14 =
    from_int(0x3fe720408f139d6e5f4b2e4fd8925060c58b2be1c240874678ed06473e9363b9)
  let fixed_eval_15 =
    from_int(0x346bc79eed23fabe8af1dc4da5704e07ac59a90ec901e7e65456cefff6844f73)
  let fixed_eval_16 =
    from_int(0x3055ecb26c30cb3c4950f0caf83585b7450d3b382119f95ded58d8ada19c645a)

  let fixed_eval_18 =
    from_int(0x6c0f77c9e74cefcafd467dd909cb547b7a7b0d6def980122644ee03290f604b3)
  let fixed_eval_19 =
    from_int(0x38cf1a5f9ffaba8d158931b79845fba2da08d4fe18b337f911d5cb3bc5fd3b99)
  let fixed_eval_20 =
    from_int(0x2bc55e2e54c94a75f50b55b2a5fd273ec970570295edc6317eeb60a68b956fc1)

  let gate_eq1 =
    add(
      add(
        add(
          add(
            add(
              add(
                add(
                  add(
                    add(
                      add(
                        add(
                          add(
                            mul(advice_eval_1, fixed_eval_1),
                            mul(advice_eval_2, fixed_eval_2),
                          ),
                          mul(advice_eval_3, fixed_eval_3),
                        ),
                        mul(advice_eval_4, fixed_eval_4),
                      ),
                      mul(advice_eval_5, fixed_eval_5),
                    ),
                    mul(mul(advice_eval_1, advice_eval_2), fixed_eval_7),
                  ),
                  mul(mul(advice_eval_3, advice_eval_4), fixed_eval_8),
                ),
                mul(fixed_eval_6, advice_eval_6),
              ),
              fixed_eval_9,
            ),
            mul(
              mul(
                mul(
                  mul(mul(advice_eval_1, advice_eval_1), advice_eval_1),
                  advice_eval_1,
                ),
                advice_eval_1,
              ),
              fixed_eval_10,
            ),
          ),
          mul(
            mul(
              mul(
                mul(mul(advice_eval_2, advice_eval_2), advice_eval_2),
                advice_eval_2,
              ),
              advice_eval_2,
            ),
            fixed_eval_11,
          ),
        ),
        mul(
          mul(
            mul(
              mul(mul(advice_eval_3, advice_eval_3), advice_eval_3),
              advice_eval_3,
            ),
            advice_eval_3,
          ),
          fixed_eval_12,
        ),
      ),
      mul(
        mul(
          mul(
            mul(mul(advice_eval_4, advice_eval_4), advice_eval_4),
            advice_eval_4,
          ),
          advice_eval_4,
        ),
        fixed_eval_13,
      ),
    )
  let gate_eq2 =
    mul(
      fixed_eval_18,
      add(
        mul(
          advice_eval_9,
          add(
            from_int(0x1),
            mul(
              mul(
                mul(
                  advice_eval_8,
                  from_int(
                    0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1,
                  ),
                ),
                mul(advice_eval_1, advice_eval_3),
              ),
              mul(advice_eval_2, advice_eval_4),
            ),
          ),
        ),
        neg(
          add(
            advice_eval_1,
            mul(
              advice_eval_8,
              add(
                add(
                  mul(advice_eval_1, advice_eval_4),
                  mul(advice_eval_3, advice_eval_2),
                ),
                neg(advice_eval_1),
              ),
            ),
          ),
        ),
      ),
    )
  let gate_eq3 =
    mul(
      fixed_eval_18,
      add(
        mul(
          advice_eval_10,
          add(
            from_int(0x1),
            neg(
              mul(
                mul(
                  mul(
                    advice_eval_8,
                    from_int(
                      0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1,
                    ),
                  ),
                  mul(advice_eval_1, advice_eval_3),
                ),
                mul(advice_eval_2, advice_eval_4),
              ),
            ),
          ),
        ),
        neg(
          add(
            advice_eval_2,
            mul(
              advice_eval_8,
              add(
                add(
                  mul(advice_eval_2, advice_eval_4),
                  mul(advice_eval_1, advice_eval_3),
                ),
                neg(advice_eval_2),
              ),
            ),
          ),
        ),
      ),
    )
  let gate_eq4 =
    mul(
      mul(fixed_eval_19, advice_eval_1),
      add(
        add(
          mul(advice_eval_2, advice_eval_2),
          neg(mul(advice_eval_1, advice_eval_1)),
        ),
        neg(
          add(
            from_int(0x1),
            mul(
              mul(
                from_int(
                  0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1,
                ),
                mul(advice_eval_1, advice_eval_1),
              ),
              mul(advice_eval_2, advice_eval_2),
            ),
          ),
        ),
      ),
    )
  let gate_eq5 =
    mul(
      mul(fixed_eval_19, advice_eval_2),
      add(
        add(
          mul(advice_eval_2, advice_eval_2),
          neg(mul(advice_eval_1, advice_eval_1)),
        ),
        neg(
          add(
            from_int(0x1),
            mul(
              mul(
                from_int(
                  0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1,
                ),
                mul(advice_eval_1, advice_eval_1),
              ),
              mul(advice_eval_2, advice_eval_2),
            ),
          ),
        ),
      ),
    )

  let lookup_table_eq1 =
    add(mul(add(mul(scalarZero, theta), fixed_eval_15), theta), fixed_eval_16)

  let lookup_input_eq1 =
    add(
      mul(add(mul(scalarZero, theta), fixed_eval_14), theta),
      mul(fixed_eval_20, advice_eval_11),
    )

  let lookup_expression_1_1 =
    mul(evaluation_at_0, sub(scalarOne, product_eval_1))
  let lookup_expression_2_1 =
    mul(
      last_evaluation,
      sub(mul(product_eval_1, product_eval_1), product_eval_1),
    )
  let lookup_left_1 =
    mul(
      mul(product_next_eval_1, add(permuted_input_eval_1, beta)),
      add(permuted_table_eval_1, gamma),
    )
  let lookup_right_1 =
    mul(
      mul(product_eval_1, add(lookup_input_eq1, beta)),
      add(lookup_table_eq1, gamma),
    )
  let lookup_expression_3_1 =
    mul(sub(lookup_left_1, lookup_right_1), active_rows)
  let lookup_expression_4_1 =
    mul(evaluation_at_0, sub(permuted_input_eval_1, permuted_table_eval_1))
  let lookup_expression_5_1 =
    mul(
      mul(
        sub(permuted_input_eval_1, permuted_table_eval_1),
        sub(permuted_input_eval_1, permuted_input_inv_eval_1),
      ),
      active_rows,
    )

  expect gate_eq1 == from_int(13)
  expect
    gate_eq2 == from_int(
      19257038036680949359750312669786877991949435402254120286184196891950884077232,
    )
  expect
    gate_eq3 == from_int(
      33178837138445241119697427838399087845741117098273517536419461807987697107279,
    )
  expect
    gate_eq4 == from_int(
      33178837138445241119697427838399087845741117098273517536419461807987697107279,
    )
  expect
    gate_eq5 == from_int(
      33178837138445241119697427838399087845741117098273517536419461807987697107279,
    )

  expect
    lookup_table_eq1 == from_int(
      0x44894772277e6b8d15c295e88d6d9fc3fd1dcd8a3f020134ece8c8f91425770b,
    )
  expect
    lookup_input_eq1 == from_int(
      0x24135b01272479a22bad9fee396bbc0435971a55b47e7e12aa34b250be6b525c,
    )
}
