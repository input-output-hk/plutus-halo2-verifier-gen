use aiken/builtin.{bls12_381_g1_neg}
use aiken/collection/list.{
  concat, filter, foldl, is_empty, length, map, push, range, unzip, zip,
}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{add as add_g1, generator, scale, zero}
use aiken/crypto/bls12_381/scalar.{Scalar, add, from_int, mul}
use lagrange.{evaluate_lagrange_polynomial}

pub type MSMElement {
  scalar: State<Scalar>,
  g1: G1Element,
}

pub type MSM {
  elements: List<MSMElement>,
}

pub fn build_msm(
  x1Powers: List<State<Scalar>>,
  x2: State<Scalar>,
  x3: State<Scalar>,
  x4Powers: List<State<Scalar>>,
  f_commitment: G1Element,
  pi_commitment: G1Element,
  proofX3QEvals: List<State<Scalar>>,
  commitmentMap: List<
    (G1Element, Int, List<State<Scalar>>, List<State<Scalar>>),
  >,
  pointSets: List<List<State<Scalar>>>,
) -> MSM {
  let point_sets_indexes = range(0, length(pointSets) - 1)

  //todo
  let (q_commitments, q_eval_sets) =
    unzip(build_q(commitmentMap, point_sets_indexes, x1Powers))
  //todo
  let f_eval =
    evaluate_lagrange_polynomial(pointSets, q_eval_sets, x2, x3, proofX3QEvals)
  // todo
  let final_com = final_commitment(q_commitments, f_commitment, x4Powers)
  // todo
  let v = compute_v(f_eval, x4Powers, proofX3QEvals)
  // todo
  append_term(
    append_term(
      final_com,
      // -vG1
      MSMElement { scalar: v, g1: bls12_381_g1_neg(generator) },
    ),
    // scaled pi
    MSMElement { scalar: x3, g1: pi_commitment },
  )
}

fn build_q(
  commitmentMap: List<
    (G1Element, Int, List<State<Scalar>>, List<State<Scalar>>),
  >,
  pointSetsIndexes: List<Int>,
  x1Powers: List<State<Scalar>>,
) -> List<(MSM, List<State<Scalar>>)> {
  map(
    pointSetsIndexes,
    fn(set_index) {
      let commitments_for_index =
        filter(commitmentMap, fn((_, idx, _, _)) { idx == set_index })
      let commitments =
        foldl(
          zip(x1Powers, commitments_for_index),
          MSM { elements: [] },
          fn((x1Power, (commitment, _, _, _)), acc) {
            append_term(acc, MSMElement { scalar: x1Power, g1: commitment })
          },
        )
      let eval_set =
        foldl(
          zip(x1Powers, commitments_for_index),
          [],
          fn((x1Power, (_, _, _, es)), acc) {
            let scaled = map(es, fn(e) { mul(e, x1Power) })

            if is_empty(acc) {
              scaled
            } else {
              map(zip(acc, scaled), fn((a, b)) { add(a, b) })
            }
          },
        )
      (commitments, eval_set)
    },
  )
}

fn final_commitment(
  q_commitments: List<MSM>,
  f_commitment: G1Element,
  x4Powers: List<State<Scalar>>,
) -> MSM {
  foldl(
    zip(
      x4Powers,
      concat(
        q_commitments,
        [
          MSM {
            elements: [MSMElement { scalar: from_int(1), g1: f_commitment }],
          },
        ],
      ),
    ),
    MSM { elements: [] },
    fn((point, msm), acc) { add_msm(acc, scale_msm(point, msm)) },
  )
}

// {-# INLINEABLE finalCommitment #-}
// -- todo this can be integrated into buildQ?
// finalCommitment ::
//     [MSM] ->
//     BuiltinBLS12_381_G1_Element ->
//     [Scalar] ->
//     MSM
// finalCommitment q_coms f_comm x4Powers =
//     foldl
//         (\accMSM (point, msm) -> addMSM accMSM (scaleMSM point msm))
//         (MSM [])
//         (zip x4Powers (q_coms ++ [MSM [MSMElem ((one :: Scalar), f_comm)]]))

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

// {-# INLINEABLE computeV #-}
// computeV ::
//     Scalar ->
//     [Scalar] ->
//     [Scalar] ->
//     Scalar
// computeV f_eval x4Powers proofX3QEvals =
//     foldl
//         (\acc (point, eval) -> acc + point * eval)
//         (zero :: Scalar)
//         (zip x4Powers (proofX3QEvals ++ [f_eval]))

fn append_term(msm: MSM, element: MSMElement) -> MSM {
  MSM { elements: push(msm.elements, element) }
}

fn add_msm(a: MSM, b: MSM) -> MSM {
  MSM { elements: concat(a.elements, b.elements) }
}

fn scale_msm(s: State<Scalar>, msm: MSM) -> MSM {
  MSM {
    elements: map(
      msm.elements,
      fn(e) { MSMElement { g1: e.g1, scalar: mul(s, e.scalar) } },
    ),
  }
}

pub fn eval(msm: MSM) -> G1Element {
  foldl(
    msm.elements,
    zero,
    fn(element, acc) { add_g1(acc, scale(element.g1, element.scalar)) },
  )
}
