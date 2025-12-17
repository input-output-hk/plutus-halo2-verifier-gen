use aiken/builtin.{blake2b_256, bls12_381_g1_neg, bls12_381_g1_scalar_mul}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{decompress, generator}
use aiken/crypto/bls12_381/scalar.{
  Scalar, from_bytes_little_endian, from_int, to_bytes_little_endian,
}
use aiken/primitive/bytearray

const prefix_challenge = #"00"

const prefix_common = #"01"

pub type Transcript {
  remaining_proof: ByteArray,
  accumulated_for_hash: ByteArray,
}

pub fn construct_transcript(
  proof: Data,
  transcript_repr: State<Scalar>,
) -> Transcript {
  expect bytes: ByteArray = proof
  let transcript =
    Transcript { remaining_proof: bytes, accumulated_for_hash: #[] }
  common_scalar(transcript_repr, transcript)
}

pub fn read_scalar(transcript: Transcript) -> (State<Scalar>, Transcript) {
  let scalar_bytes = bytearray.take(transcript.remaining_proof, 32)
  let scalar = from_bytes_little_endian(scalar_bytes)

  let remaining_proof_data = bytearray.drop(transcript.remaining_proof, 32)

  let bytes_to_append = bytearray.concat(prefix_common, scalar_bytes)
  let new_bytes_for_hash =
    bytearray.concat(transcript.accumulated_for_hash, bytes_to_append)
  (
    scalar,
    Transcript {
      remaining_proof: remaining_proof_data,
      accumulated_for_hash: new_bytes_for_hash,
    },
  )
}

pub fn common_scalar(
  scalar: State<Scalar>,
  transcript: Transcript,
) -> Transcript {
  let scalar_bytes = to_bytes_little_endian(scalar)

  let bytes_to_append = bytearray.concat(prefix_common, scalar_bytes)
  let new_bytes_for_hash =
    bytearray.concat(transcript.accumulated_for_hash, bytes_to_append)

  Transcript { ..transcript, accumulated_for_hash: new_bytes_for_hash }
}

pub fn read_point(transcript: Transcript) -> (ByteArray, Transcript) {
  let g1_bytes = bytearray.take(transcript.remaining_proof, 48)
  let remaining_proof_data = bytearray.drop(transcript.remaining_proof, 48)

  let bytes_to_append = bytearray.concat(prefix_common, g1_bytes)
  let new_bytes_for_hash =
    bytearray.concat(transcript.accumulated_for_hash, bytes_to_append)

  (
    g1_bytes,
    Transcript {
      remaining_proof: remaining_proof_data,
      accumulated_for_hash: new_bytes_for_hash,
    },
  )
}

pub fn squeeze_challenge(transcript: Transcript) -> (State<Scalar>, Transcript) {
  let data_for_squeeze =
    bytearray.concat(transcript.accumulated_for_hash, prefix_challenge)
  let squeeze_hash = blake2b_256(data_for_squeeze)
  let squeeze_scalar = from_bytes_little_endian(squeeze_hash)

  (
    squeeze_scalar,
    Transcript { ..transcript, accumulated_for_hash: data_for_squeeze },
  )
}

test transcript_representation_test() {
  let rep =
    from_int(0x53772fda8c4d27d16e6d1b3b0ed0f0c492414695f8050480aaeb9f0c1257bc6b)
  let proof_for_testing = #"00"

  let transcript_data = construct_transcript(proof_for_testing, rep)
  let (squeeze, _) = squeeze_challenge(transcript_data)
  expect
    squeeze == from_int(
      0x4adae634053c0c9ed84859d0be4afad0dce2a7fe3e3e29e09a02e19d603022ad,
    )
}

test point_deserialization_generator() {
  let rep = from_int(1)

  let generator_bytes =
    #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

  let transcript_data = construct_transcript(generator_bytes, rep)
  let (point, _) = read_point(transcript_data)
  let point = decompress(point)

  expect generator == point
}

test point_deserialization_negated_generator() {
  let rep = from_int(1)

  let negated_generator_bytes =
    #"b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

  let transcript_data = construct_transcript(negated_generator_bytes, rep)
  let (point, _) = read_point(transcript_data)
  let point = decompress(point)

  expect bls12_381_g1_neg(generator) == point
}

test point_deserialization() {
  let rep = from_int(1)
  let point_bytes =
    #"8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"
  let transcript_data = construct_transcript(point_bytes, rep)
  let (point, _) = read_point(transcript_data)
  let point = decompress(point)

  expect bls12_381_g1_scalar_mul(42, generator) == point
}

test scalar_deserialization_field_prime() {
  let rep = from_int(1)
  let scalar_bytes =
    #"01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"

  let transcript_data = construct_transcript(scalar_bytes, rep)
  let (scalar, _) = read_scalar(transcript_data)

  expect scalar == from_int(0)
}

test overflow_scalar_deserialization() {
  let rep = from_int(1)
  let scalar_bytes =
    #"01000000fffffffffe5bfeff42a4bd5305d8a10908d83933487d9d2953a7ed71"
  let transcript_data = construct_transcript(scalar_bytes, rep)
  let (scalar, _) = read_scalar(transcript_data)
  expect
    scalar == from_int(
      0x71eda753299d7d483339d80809a1d80553bda442fffe5bfeffffffff00000001,
    )
}

test adding_scalar_to_transcript() {
  let rep = from_int(1)
  let proof_for_testing = #"00"

  let c_scalar = from_int(42)

  let transcript_data = construct_transcript(proof_for_testing, rep)
  let transcript_data = common_scalar(c_scalar, transcript_data)

  let (challenge, _) = squeeze_challenge(transcript_data)

  expect
    challenge == from_int(
      0x6190bbe89273a593347609a54a42f88bb174cb94062a8dc9763f2f9d82862e9,
    )
}

test squeeze_challenge_calculations() {
  let rep = from_int(1)
  let proof_for_testing =
    #"b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb01000000fffffffffe5bfeff42a4bd5305d8a10908d83933487d9d2953a7ed71"

  let c_scalar = from_int(42)

  let transcript_data = construct_transcript(proof_for_testing, rep)
  let transcript_data = common_scalar(c_scalar, transcript_data)
  let (point, transcript_data) = read_point(transcript_data)
  let point = decompress(point)
  let (scalar, transcript_data) = read_scalar(transcript_data)
  let (challenge, _) = squeeze_challenge(transcript_data)

  expect bls12_381_g1_neg(generator) == point
  expect
    scalar == from_int(
      0x71eda753299d7d483339d80809a1d80553bda442fffe5bfeffffffff00000001,
    )
  expect
    challenge == from_int(
      0x953016816a1528fef2fc6314ea3929ebebd9bbe9d315539251c205bd82408c5,
    )
}

// reference data was generated with Plinth verifier example, by using tracing feature
// this test is based on simple mul example run with halo2 flavor of KZG
test full_proof_deserialization_for_simple_mul_circuit() {
  let transcript_repr_for_tests =
    0x53772fda8c4d27d16e6d1b3b0ed0f0c492414695f8050480aaeb9f0c1257bc6b

  let proof_for_testing =
    #"b248ab31621cfaac32f093c051c410a09744dd0faef7fa25671d6f4274932c62f1d72ca31eeec56c07d54e3df4b322e7959ed03170f4ac2ea7bedf73c64142024d7b1fa4fcd0d4e408215a0bde731d4d43ea8aa30a94d702dd13a63179a47b46b7848d5311d369df05a761e23b25c90b3b810ee7d85fe5ed46aefa037bfdfdaaede878552f24842fc6a31b1d70df8f07995879f9a52d481b6c2700016eb4d13b4147bd494d31f373b8b21ad7ffb7db5e719a6ab4b74e45c4b64aa87553a7ccf4a211b5a2ee6cebcb79849e4d9bc5c6b87a645a1651a28ce0f9db347f12008af6f3928398d4e66bb4c7e567644bff848ab1ed947d0c22c55430e39be31033df0ed216861ff8b52ed01cb98045e5951b4937d14ae7921a67f502a6d2c0d5bb20a795e8c31bfe7bb9be7fa3a7da7b8465cb87b1657e6968d78c851955fc7642d70ad9b046a94fa6959819f959ef05696ec8815d30e16a52d63df8b74536e4151e669c825b8b9d9729e897bcdebe830024c823a57c690178234b73c2d52ed2d02aad860a487c7f91cb01bdbc1095533a34a41bdae166b408789d05f62cb61060f705915836cf5e03d956a93a7fb4dad11de340029452006096ff4597bfaed534f704e4ebd072f0f5beaaec4f51517eedad116ce6046c0b8bcfabe95232246e14221eb455f7c239b40c16ffb085a453aab2f9d7d7c83bd86f779deaa8ae7c77756a374ccdfc541c5f3965e976ed3bd4d19e9b3002510452a1fc1bff735e61ad6a6f472f95f339e24cb033ae8c718164b44d39fecc3fab3313b26ff8a88f5622d58d0d255f6144303902cb443e2c7b1e0e3cee914c9aee7dcc851d27b185ea37bfc1504492649923e583070053b325fa38966953a5147a12b6ce38ca094c699c692f67ceb92b0671b2c711676f69580e89c0e4094d2bb073d658be83fdc11e14cc853425112482072e73aeab1621b301b79d4caa163c880e8720a35f674902b47b7f3911441727855036eb317fb1ebff0bef31edd9edbbc7e5346a936e786176cefd17115370fde14f5e3b359f9493a656b761de5f7581e05350fdad0b250e3be84852e14e78c81770aa6f379555c950b10c01285de389a6f4a4c9e778c67536c103024314e39f676a4902381323980cd49a2a9bb6c276c2da040b849e924cf6094262d04a04df7b9771a5d078bbdfd6172c53152b0ebf1cc922162777c7428f68434eec1311d5566f978bcaaf146e74be78af5288af409a253c2dacfd741bf5990859c3707841337140cb86d54a1269ae0c79c85a45100d43cdea227e579934c7385c8aca806eb430a5c6498d9785a4b59fe8acf3860918477c782c9eb9bde51daa069acf42968806b5764786c2a703917b7307585e311aabdc2aee0138736410725080133eb21afe4f01d196e6dce8e49a33b03aa89d135bce20f7cb1310eb915c85503c5f1b44d3fb05f9d0132115dfc639fdf8f10bc6e841d2e903ac52e528f3f779f1e11b1aa993799b63b9f43d1ddc2f828567b7479c21b7972dacb8cceb8875fcdcb972287b596f5f635dd3ecfefa6e969ebb60198032d24c6c93bc8b3bfac6"

  let rep = from_int(transcript_repr_for_tests)

  let inputs_count = from_int(3)
  let inputs_1 = from_int(42)
  let inputs_2 = from_int(42)
  let inputs_3 = from_int(42)

  let transcript_data = construct_transcript(proof_for_testing, rep)

  let transcript_data = common_scalar(inputs_count, transcript_data)

  let transcript_data = common_scalar(inputs_1, transcript_data)
  let transcript_data = common_scalar(inputs_2, transcript_data)
  let transcript_data = common_scalar(inputs_3, transcript_data)

  let (_a1, transcript_data) = read_point(transcript_data)
  let (_a2, transcript_data) = read_point(transcript_data)

  let (_theta, transcript_data) = squeeze_challenge(transcript_data)
  let (_beta, transcript_data) = squeeze_challenge(transcript_data)
  let (gamma, transcript_data) = squeeze_challenge(transcript_data)

  expect
    gamma == from_int(
      0x581743998eb1b602aa993ad12813fac838fe438153b29827d5216c98c4471960,
    )

  let (_permutations_committed_a, transcript_data) = read_point(transcript_data)
  let (_permutations_committed_b, transcript_data) = read_point(transcript_data)
  let (_permutations_committed_c, transcript_data) = read_point(transcript_data)

  let (_vanishingRand, transcript_data) = read_point(transcript_data)

  let (y, transcript_data) = squeeze_challenge(transcript_data)

  expect
    y == from_int(
      0x4b57e2385bb505b146a1fd814e70f776617d92b8c413a9d6d369c6865fd01870,
    )

  let (_vanishingSplit1, transcript_data) = read_point(transcript_data)
  let (_vanishingSplit2, transcript_data) = read_point(transcript_data)

  let (x, transcript_data) = squeeze_challenge(transcript_data)

  expect
    x == from_int(
      0x65e2000f8ef4d864b59536948015f6d968e559ecaccae4d58aea34b54593652d,
    )

  let (adviceEval1, transcript_data) = read_scalar(transcript_data)
  let (adviceEval2, transcript_data) = read_scalar(transcript_data)
  let (adviceEval3, transcript_data) = read_scalar(transcript_data)

  expect
    adviceEval1 == from_int(
      0x5f76010b62cf6059d7808b466e1da1ba4343a539510bcbd01cb917f7c480a86,
    )

  expect
    adviceEval2 == from_int(
      0x4f734d5aebf9745ff96600052940240e31dd1dab47f3aa956d9035ecf365891,
    )

  expect
    adviceEval3 == from_int(
      0x1e22146e243252e9abcf8b0b6c04e66c11aded7e51514fecaabef5f072d0ebe4,
    )

  let (_fixedEval1, transcript_data) = read_scalar(transcript_data)
  let (_fixedEval2, transcript_data) = read_scalar(transcript_data)

  let (_randomEval, transcript_data) = read_scalar(transcript_data)

  let (_permutationCommon1, transcript_data) = read_scalar(transcript_data)
  let (_permutationCommon2, transcript_data) = read_scalar(transcript_data)
  let (_permutationCommon3, transcript_data) = read_scalar(transcript_data)

  let (_permutations_evaluated_a_1, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_a_2, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_a_3, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_b_1, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_b_2, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_b_3, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_c_1, transcript_data) =
    read_scalar(transcript_data)
  let (_permutations_evaluated_c_2, transcript_data) =
    read_scalar(transcript_data)

  let (x1, transcript_data) = squeeze_challenge(transcript_data)
  let (x2, transcript_data) = squeeze_challenge(transcript_data)

  expect
    x1 == from_int(
      0x25dbe380cca31996adfe0536275c9fe0e70f4c00c87bfe2df90d6dcbd9c6c643,
    )
  expect
    x2 == from_int(
      0x453fe79d8e3a830d417882a1403b735fe5150db8de91c8277e4bca08eb8c9830,
    )
  let (_f_commitment, transcript_data) = read_point(transcript_data)
  let (x3, transcript_data) = squeeze_challenge(transcript_data)

  expect
    x3 == from_int(
      0x6c180a84842b308c78d360330b43eb74047473918589c83ff05e2971b82a7025,
    )

  let (_q_eval_on_x3_1, transcript_data) = read_scalar(transcript_data)
  let (_q_eval_on_x3_2, transcript_data) = read_scalar(transcript_data)
  let (_q_eval_on_x3_3, transcript_data) = read_scalar(transcript_data)

  let (x4, transcript_data) = squeeze_challenge(transcript_data)

  let (pi_term, _) = read_point(transcript_data)
  let pi_term = decompress(pi_term)

  expect
    x4 == from_int(
      0x4a458f7c6a72c5efa4756daf7379ed4dd6e676306741a3bf08e3061eda88ab0f,
    )

  let expected_point =
    decompress(
      #"828567b7479c21b7972dacb8cceb8875fcdcb972287b596f5f635dd3ecfefa6e969ebb60198032d24c6c93bc8b3bfac6",
    )

  expect pi_term == expected_point
}
