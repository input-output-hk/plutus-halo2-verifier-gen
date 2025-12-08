use aiken/collection/list.{foldl, map, reverse, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, add, from_int, mul, sub, sub_int}
use bls_utils.{recip_eea}

// TODO: Revert to this version of lagrange_evaluation when CIP-109 with built-in inverse is available, because it will be faster than batch_inverses
// fn lagrange_evaluation(
//   points: List<(State<Scalar>, State<Scalar>)>,
//   x: State<Scalar>,
// ) -> State<Scalar> {
//   foldl(
//     points,
//     from_int(0),
//     fn((xi, yi), acc) { add(acc, mul(yi, basis(x, xi, points))) },
//   )
// }

// fn basis(
//   x: State<Scalar>,
//   xi: State<Scalar>,
//   points: List<(State<Scalar>, State<Scalar>)>,
// ) -> State<Scalar> {
//   let (total_numerator, total_denominator) =
//     foldl(
//       points,
//       (from_int(1), from_int(1)),
//       fn((xj, _), (numerator, denominator)) {
//         if !(xj == xi) {
//           (mul(numerator, sub(x, xj)), mul(denominator, sub(xi, xj)))
//         } else {
//           (numerator, denominator)
//         }
//       },
//     )
//   let total_denominator = recip_eea(total_denominator)
//   mul(total_numerator, total_denominator)
// }

// Optimized lagrange_evaluation using batch_inverses
pub fn lagrange_evaluation(
  points: List<(State<Scalar>, State<Scalar>)>,
  x: State<Scalar>,
) -> State<Scalar> {
  // Step 1: Compute all (numerator, denominator, yi) tuples
  let basis_data =
    map(
      points,
      fn((xi, yi)) {
        let (num, denom) =
          foldl(
            points,
            (from_int(1), from_int(1)),
            fn((xj, _), (numerator, denominator)) {
              if xj == xi {
                (numerator, denominator)
              } else {
                (mul(numerator, sub(x, xj)), mul(denominator, sub(xi, xj)))
              }
            },
          )
        (num, denom, yi)
      },
    )

  // Step 2: Extract denominators and batch invert (1 recip instead of N!)
  let denominators = map(basis_data, fn((_, denom, _)) { denom })
  let inverted_denominators = batch_inverses(denominators)

  // Step 3: Compute final sum
  foldl(
    zip(basis_data, inverted_denominators),
    from_int(0),
    fn(((num, _, yi), denom_inv), acc) {
      add(acc, mul(yi, mul(num, denom_inv)))
    },
  )
}

pub fn lagrange_polynomial_basis(
  x: State<Scalar>,
  xn: State<Scalar>,
  barycentric_weight: State<Scalar>,
  rotations: List<State<Scalar>>,
) -> List<State<Scalar>> {
  let common = mul(sub_int(xn, 1), barycentric_weight)
  // TODO: when CIP-109 is implemented and built-in inversion is available, replace batch_inverses as follows
  // let inverses =
  //   map(
  //     rotations,
  //     fn(rotated_omega) { recip(sub(x, rotated_omega)) },
  //   )
  let inverses =
    batch_inverses(map(rotations, fn(rotated_omega) { sub(x, rotated_omega) }))
  let zipped = zip(inverses, rotations)
  map(zipped, fn((inv, rotated_omega)) { mul(mul(inv, common), rotated_omega) })
}

pub fn batch_inverses(elements: List<State<Scalar>>) -> List<State<Scalar>> {
  when elements is {
    [] -> []
    [a, ..a_cons] -> {
      // Build reversed cumulative products
      let b_rev =
        foldl(
          a_cons,
          [a],
          fn(elem, accum) {
            expect [head_accum, ..] = accum
            [mul(elem, head_accum), ..accum]
          },
        )

      let a_rev = reverse(elements)

      expect [head_b_rev, ..tail_b_rev] = b_rev
      let b_inv_last = recip_eea(head_b_rev)

      let (a_inv_acc, b_inv_1) =
        foldl(
          zip(tail_b_rev, a_rev),
          ([], b_inv_last),
          fn((b_i_min_1, a_i), (a_inv_accum, b_inv_i)) {
            ([mul(b_inv_i, b_i_min_1), ..a_inv_accum], mul(b_inv_i, a_i))
          },
        )

      [b_inv_1, ..a_inv_acc]
    }
  }
}

// values based on atms circuit results
test calculate_lagrange_basis() {
  let x =
    from_int(0x27267acdcdde9716fe9323b98bc0930dd54e5dc1f0b5c59dfcdd83f92eb5f2e4)
  let xn =
    from_int(0x704a1af8e8913f64ae2432b58446ec9a9a591f7ddce6fef2461e745176248f64)
  let barycentric_weight =
    from_int(0x73ebd79c8c50d6d23e190b20a981b17df3a8550c6ff25c059003ffff00040001)
  let rotations =
    [
      from_int(
        0xb86cb0cc9981913c405642e1a61b6c2ebb2c035b286d62963161b0e604f2b5c,
      ),
      from_int(
        0x2d81596dda5e65d78aa2fbc9a41187afb2125a3ed8061f1633d09f0c1577c836,
      ),
      from_int(
        0x391b2856c609b4784ae25ffab9dc59865046d17864183203961a252dd8543362,
      ),
      from_int(
        0x1cd54bc8adcd5dab7989ec74ae3f47f4588f2deee2a0d9a40404e47eecd35df7,
      ),
      from_int(
        0x57e6990d4981b177d548fda262008419204f9476cecef2df68946aad325251ed,
      ),
      from_int(
        0x281f74790b85a216fd013df1f683bf99a14c38253fdb838cd7a1f5bc8f529599,
      ),
      from_int(1),
    ]
  let result = lagrange_polynomial_basis(x, xn, barycentric_weight, rotations)
  expect
    [
      from_int(
        0xa2fe3f7fde64d7d605591ce4aea98af72909596cd0c00b804fbfafa1f901ef1,
      ),
      from_int(
        0x6cd49ccc922112fb9ee9991410cd221a8ab6250d3de49526ed89bf78a7df7825,
      ),
      from_int(
        0x471ea2d1941c679e4a0b618316edf29a26934fefda54185c7461951a6ca6aee9,
      ),
      from_int(
        0x4857a3cecf94d627e8bddced4b4791bb4f4db40e3e62bed7e1dac2f6d3712f4b,
      ),
      from_int(
        0x249dedd80add27339f6cce5a9e48b024a41888f4ca15882b696bb27cc49c027c,
      ),
      from_int(
        0x549b3d7ffdb0463d57b20cf3968a2ddaf267e442fe0dc5b30b2e98e0c96a358c,
      ),
      from_int(
        0x54ab6e351835f0093a6dabb8b14c7707a6704894ada9b60294e9bbfab856347f,
      ),
    ] == result
}
