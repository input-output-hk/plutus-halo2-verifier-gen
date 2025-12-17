use aiken/collection/list.{
  concat, foldl, foldl2, foldr2, is_empty, last, map, map2, map3, push, reverse, zip,
}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{add as add_g1, decompress, scale, zero}
use aiken/crypto/bls12_381/scalar.{Scalar, add, from_int, mul, sub}
use lagrange.{batch_inverses, lagrange_evaluation}
use verifier_key.{neg_g1_generator}

// Computes MSM for verifying multiple openings in the KZG polynomial commitment scheme (the multi-open protocol from the Halo2 book).
// It represents the `right` input to the pairing check equation: `e(left, sG2) == e(right, G2)`,
// where `left` is PI commitment.
// For reference implementation, see `https://github.com/input-output-hk/halo2/blob/plutus_verification/src/poly/kzg/mod.rs#L193`

pub fn compute_msm(
  x1Powers: List<State<Scalar>>,
  x2: State<Scalar>,
  x3: State<Scalar>,
  x4Powers: List<State<Scalar>>,
  f_commitment: ByteArray,
  pi_commitment: ByteArray,
  proofX3QEvals: List<State<Scalar>>,
  commitmentMap: List<List<(ByteArray, List<State<Scalar>>)>>,
  pointSets: List<List<State<Scalar>>>,
) -> G1Element {
  let final_com, q_eval_sets <-
    compute_q_evals_and_final_comm(
      commitmentMap,
      x1Powers,
      x4Powers,
      f_commitment,
    )

  let f_eval = compute_f_eval(pointSets, q_eval_sets, x2, x3, proofX3QEvals)
  let v = compute_v(f_eval, x4Powers, proofX3QEvals)

  add_g1(
    final_com,
    add_g1(
      scale(decompress(neg_g1_generator), v),
      scale(decompress(pi_commitment), x3),
    ),
  )
}

fn compute_q_evals_and_final_comm(
  commitmentMap: List<List<(ByteArray, List<State<Scalar>>)>>,
  x1Powers: List<State<Scalar>>,
  x4Powers: List<State<Scalar>>,
  f_commitment: ByteArray,
  continue: fn(G1Element, List<List<State<Scalar>>>) -> a,
) -> a {
  let final_comm, q_eval_sets <-
    foldr2(
      zip(commitmentMap, x4Powers),
      zero,
      [],
      fn((commitments_for_set, x4Power), acc1, acc2, return) {
        let q_comms, eval_set <-
          foldl2(
            zip(x1Powers, commitments_for_set),
            zero,
            [],
            fn((x1Power, (commitment, es)), acc1, acc2, return) {
              let acc1 = add_g1(acc1, scale(decompress(commitment), x1Power))
              let acc2 = {
                if is_empty(acc2) {
                  map(es, fn(e) { mul(e, x1Power) })
                } else {
                  map2(acc2, es, fn(a, b) { add(a, mul(b, x1Power)) })
                }
              }
              return(acc1, acc2)
            }
          )

        // scale Q commitments by x4Powers and accumulate them in final commitment
        let acc1 = add_g1(acc1, scale(q_comms, x4Power))
        let acc2 = push(acc2, eval_set)
        return(acc1, acc2)
      }
    )

  // We also need to add the f_commitment scaled by the last x4Power
  expect Some(x4Power) = last(x4Powers)
  let final_comm = add_g1(final_comm, scale(decompress(f_commitment), x4Power))

  continue(final_comm, q_eval_sets)
}

// TODO: Revert to this version of `compute_f_eval` when CIP-109 with built-in inverse is available, 
//       because it will be faster than batch_inverses
// pub fn compute_f_eval(
//   point_sets: List<List<State<Scalar>>>,
//   q_eval_sets: List<List<State<Scalar>>>,
//   x2: State<Scalar>,
//   x3: State<Scalar>,
//   proof_X3_q_evals: List<State<Scalar>>,
// ) -> State<Scalar> {
//   foldl(
//     reverse(zip(point_sets, zip(q_eval_sets, proof_X3_q_evals))),
//     from_int(0),
//     fn((points, (evals, proofQEval)), acc_eval) {
//       let r_eval = lagrange_evaluation(zip(points, evals), x3)
//       let denominator =
//         recip(
//           foldl(
//             points,
//             from_int(1),
//             fn(point, acc) { mul(acc, sub(x3, point)) },
//           ),
//         )
//       let evaluation = mul(sub(proofQEval, r_eval), denominator)

//       add(mul(acc_eval, x2), evaluation)
//     },
//   )
// }

// Optimized with batch_inverses - replaces N recip_eea calls with 1
pub fn compute_f_eval(
  point_sets: List<List<State<Scalar>>>,
  q_eval_sets: List<List<State<Scalar>>>,
  x2: State<Scalar>,
  x3: State<Scalar>,
  proof_X3_q_evals: List<State<Scalar>>,
) -> State<Scalar> {
  // Step 1: Compute r_evals and denominators for all point sets (no inversions yet)
  let data =
    map3(
      point_sets,
      q_eval_sets,
      proof_X3_q_evals,
      fn(points, evals, proofQEval) {
        let r_eval = lagrange_evaluation(zip(points, evals), x3)
        let denom =
          foldl(
            points,
            from_int(1),
            fn(point, acc) { mul(acc, sub(x3, point)) },
          )
        (r_eval, denom, proofQEval)
      },
    )

  // Step 2: Extract denominators and batch invert (1 recip instead of N)
  let denominators = map(data, fn((_, denom, _)) { denom })
  let inverted_denominators = batch_inverses(denominators)

  // Step 3: Compute final result with inverted denominators
  foldl(
    reverse(zip(data, inverted_denominators)),
    from_int(0),
    fn(((r_eval, _, proofQEval), denom_inv), acc_eval) {
      let evaluation = mul(sub(proofQEval, r_eval), denom_inv)
      add(mul(acc_eval, x2), evaluation)
    },
  )
}

fn compute_v(
  f_eval: State<Scalar>,
  x4Powers: List<State<Scalar>>,
  proofX3QEvals: List<State<Scalar>>,
) -> State<Scalar> {
  foldl(
    zip(x4Powers, concat(proofX3QEvals, [f_eval])),
    from_int(0),
    fn((point, eval), acc) { add(acc, mul(point, eval)) },
  )
}
