
3

let (a1, transcript) = read_point(transcript)
let (a2, transcript) = read_point(transcript)
let (theta, transcript) = squeeze_challenge(transcript)
let (beta, transcript) = squeeze_challenge(transcript)
let (gamma, transcript) = squeeze_challenge(transcript)
let (permutations_committed_a, transcript) = read_point(transcript)
let (permutations_committed_b, transcript) = read_point(transcript)
let (permutations_committed_c, transcript) = read_point(transcript)
let (vanishing_rand, transcript) = read_point(transcript)
let (y, transcript) = squeeze_challenge(transcript)
let (vanishing_split1, transcript) =  read_point(transcript)
let (vanishing_split2, transcript) =  read_point(transcript)
let (x, transcript) = squeeze_challenge(transcript)
let (advice_eval1, transcript) = read_scalar(transcript)
let (advice_eval2, transcript) = read_scalar(transcript)
let (advice_eval3, transcript) = read_scalar(transcript)
let (fixed_eval1, transcript) = read_scalar(transcript)
let (fixed_eval2, transcript) = read_scalar(transcript)
let (random_eval, transcript) = read_scalar(transcript)
let (permutation_common1, transcript) = read_scalar(transcript)
let (permutation_common2, transcript) = read_scalar(transcript)
let (permutation_common3, transcript) = read_scalar(transcript)
let (permutations_evaluated_a_1, transcript) = read_scalar(transcript)
let (permutations_evaluated_a_2, transcript) = read_scalar(transcript)
let (permutations_evaluated_a_3, transcript) = read_scalar(transcript)
let (permutations_evaluated_b_1, transcript) = read_scalar(transcript)
let (permutations_evaluated_b_2, transcript) = read_scalar(transcript)
let (permutations_evaluated_b_3, transcript) = read_scalar(transcript)
let (permutations_evaluated_c_1, transcript) = read_scalar(transcript)
let (permutations_evaluated_c_2, transcript) = read_scalar(transcript)
let (x1, transcript) = squeeze_challenge(transcript)
let (x2, transcript) = squeeze_challenge(transcript)
let (f_commitment, transcript) =  read_point(transcript)
let (x3, transcript) = squeeze_challenge(transcript)
let (q_eval_on_x3_1, transcript) = read_scalar(transcript)
let (q_eval_on_x3_2, transcript) = read_scalar(transcript)
let (q_eval_on_x3_3, transcript) = read_scalar(transcript)
let (x4, transcript) = squeeze_challenge(transcript)
let (pi_term, transcript) =  read_point(transcript)


16

let gate_eq1 = mul(fixed_eval_2, add(mul(advice_eval_1, advice_eval_2),  neg(advice_eval_3) ))







