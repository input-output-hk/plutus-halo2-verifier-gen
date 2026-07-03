use anyhow::{Context as _, Result, anyhow};
use log::info;
use midnight_zk_stdlib::MidnightCircuit;

use base64::{STANDARD_NO_PAD, decode_config};
use midnight_circuits::{
    field::foreign::{AssignedField, params::MultiEmulationParams},
    instructions::{
        AssertionInstructions, AssignmentInstructions, Base64Instructions,
        DecompositionInstructions, EccInstructions, RangeCheckInstructions,
        public_input::CommittedInstanceInstructions,
    },
    parsing::{DateFormat, Separator, StdLibParser},
    testing_utils::ecdsa::{ECDSASig, FromBase64},
    types::{AssignedByte, AssignedForeignPoint, AssignedNative},
};
use midnight_curves::k256::{Fq as secp256k1Scalar, K256};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::{Error, commit_to_instances},
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
use num_bigint::BigUint;
use utils::{read_credential, split_blob, verify_credential_sig};

use midnight_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::commitment::Guard,
    poly::kzg::{
        KZGCommitmentScheme,
        params::{ParamsKZG, ParamsVerifierKZG},
    },
    transcript::{CircuitTranscript, Transcript},
};

use midnight_circuits::CircuitField;
use midnight_curves::{Bls12, BlsScalar as Scalar};
use plutus_halo2_verifier_gen::{
    kzg_params::get_or_create_kzg_params,
    plutus_gen::{CardanoFriendlyBlake2b, generate_aiken_verifier, generate_plinth_verifier},
};
use rand::SeedableRng;
use rand::prelude::StdRng;

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

mod utils {
    use std::{fs::OpenOptions, io::Read};

    use midnight_circuits::{
        CircuitField,
        testing_utils::ecdsa::{ECDSASig, Ecdsa, FromBase64},
    };
    use midnight_curves::k256::{Fq as secp256k1Scalar, K256};
    use midnight_proofs::plonk::Error;
    use sha2::Digest;

    // Reads a credential of up to MAX bytes from the specified path.
    pub(crate) fn read_credential<const MAX: usize>(path: &str) -> Result<Vec<u8>, Error> {
        let mut fd = OpenOptions::new().read(true).open(path)?;
        let mut buf = vec![0u8; MAX];
        let len = fd.read(buf.as_mut_slice())?;
        let content = std::str::from_utf8(&buf[..len]).expect("Credential should be valid UTF-8");
        Ok(content.trim_end().as_bytes().into())
    }

    /// Splits a JWT blob in its 3 parts:
    ///  * header
    ///  * body
    ///  * signature
    ///
    /// The signature is computed over payload := (header || body).
    /// Returns the payload and the signature.
    /// For reference: <https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-structure>
    pub(crate) fn split_blob(blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut parts = blob.split(|char| *char as char == '.');

        let header = parts.next().unwrap();
        let body = parts.next().unwrap();
        let signature = parts.next().unwrap();

        assert!(parts.next().is_none());

        let payload = [header, b".", body].concat();
        let signature = signature.to_vec();

        (payload, signature)
    }

    /// Verifies the signature of a credential (out of circuit).
    /// The public key, message (or payload) and signature are expected in base64
    /// encoding.
    pub(crate) fn verify_credential_sig(pk_base64: &[u8], msg: &[u8], sig_base64: &[u8]) -> bool {
        let pk_affine = K256::from_base64(pk_base64).unwrap();
        let sig = ECDSASig::from_base64(sig_base64).unwrap();

        let mut msg_hash_bytes: [u8; 32] = sha2::Sha256::digest(msg).into();
        msg_hash_bytes.reverse(); // BE to LE
        let msg_scalar = secp256k1Scalar::from_bytes_be(&msg_hash_bytes).unwrap();

        Ecdsa::verify(&pk_affine, &msg_scalar, &sig)
    }
}

type F = midnight_curves::Fq;

const CRED_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/2k-credential");

// Public Key of the issuer, signer of the credential.
const PUB_KEY: &[u8] =
    b"_bDXlQJ636HHOvXSe-flG0f-OkkRu8Jusm93PB2GBjoykg753nsOiW1vhEpCnxxybkMdarJLXIUJIYw1K2emQI";

// Secret key of the credential holder.
const HOLDER_SK_BYTES: [u8; 32] = [
    0xc4, 0xe0, 0x5a, 0x8e, 0xc1, 0x68, 0x35, 0xce, 0x36, 0xf0, 0x9f, 0xcb, 0x94, 0x10, 0x08, 0x33,
    0xc8, 0x2d, 0xba, 0xe7, 0x85, 0xc0, 0x08, 0x36, 0x87, 0xc2, 0x51, 0xf4, 0x0a, 0xc6, 0xa5, 0x5e,
];

const HEADER_LEN: usize = 38;
const PAYLOAD_LEN: usize = 2463;

// Credential payload.
type Payload = [u8; PAYLOAD_LEN];
// Holder secret key.
type SK = secp256k1Scalar;

#[derive(Clone, Default)]
pub struct CredentialProperty;

const MAX_VALID_DATE: Date = Date {
    day: 1,
    month: 1,
    year: 2004,
};

const VALID_NAME: &[u8] = b"Alice";
const NAME_LEN: usize = VALID_NAME.len(); // TODO: this value should not be fixed.
const BIRTHDATE_LEN: usize = 10;
const COORD_LEN: usize = 43;

impl Relation for CredentialProperty {
    type Instance = ();
    type Witness = (Payload, SK);
    type Error = Error;

    fn format_instance(_instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![])
    }

    fn format_committed_instances(witness: &Self::Witness) -> Vec<F> {
        let json_b64 = &witness.0[HEADER_LEN + 1..PAYLOAD_LEN];
        let json = base64::decode_config(json_b64, base64::STANDARD_NO_PAD)
            .expect("Valid base64 encoded JSON.");
        let res: Vec<midnight_curves::Fq> = json.iter().map(|byte| F::from(*byte as u64)).collect();
        res
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let secp256k1_curve = std_lib.secp256k1();
        let b64_chip = std_lib.base64();
        let automaton_chip = std_lib.scanner();

        let (json, sk) = witness.unzip();

        // Assign decoded Base64 JSON
        let json: Vec<AssignedByte<_>> = {
            let len = (PAYLOAD_LEN - (HEADER_LEN + 1)) / 4 * 3;
            let vals = json
                .map(|json| {
                    let json_b64 = &json[HEADER_LEN + 1..PAYLOAD_LEN];
                    decode_config(json_b64, STANDARD_NO_PAD).expect("Valid base64 encoded JSON.")
                })
                .transpose_vec(len);
            std_lib.assign_many(layouter, vals.as_slice())?
        };

        // Constrains as committed instance (to link with enrollment proof).
        for byte in json.iter() {
            let byte_as_f: AssignedNative<_> = byte.into();
            std_lib.constrain_as_committed_public_input(layouter, &byte_as_f)?;
        }

        let parsed_json = automaton_chip.parse(layouter, StdLibParser::Jwt.into(), &json)?;

        // // Check Name.
        let name = Self::get_property(std_lib, layouter, &json, &parsed_json, 3, NAME_LEN)?;
        Self::assert_str_match(std_lib, layouter, &name, VALID_NAME)?;

        // Check birth date.
        let birthdate =
            Self::get_property(std_lib, layouter, &json, &parsed_json, 4, BIRTHDATE_LEN)?;
        Self::assert_date_before(std_lib, layouter, &birthdate, MAX_VALID_DATE)?;

        // Get holder public key.
        let x = Self::get_property(std_lib, layouter, &json, &parsed_json, 5, COORD_LEN)?;
        let y = Self::get_property(std_lib, layouter, &json, &parsed_json, 6, COORD_LEN)?;
        let x_val = b64_chip.decode_base64url(layouter, &x, false)?;
        let y_val = b64_chip.decode_base64url(layouter, &y, false)?;

        // Check knowledge of corresponding sk.
        let x_coord = secp256k1_curve
            .base_field_chip()
            .assigned_from_be_bytes(layouter, &x_val[..32])?;
        let y_coord = secp256k1_curve
            .base_field_chip()
            .assigned_from_be_bytes(layouter, &y_val[..32])?;

        let holder_pk = secp256k1_curve.point_from_coordinates(layouter, &x_coord, &y_coord)?;
        let holder_sk: AssignedField<_, secp256k1Scalar, MultiEmulationParams> = std_lib
            .secp256k1()
            .scalar_field_chip()
            .assign(layouter, sk)?;

        let gen_point: AssignedForeignPoint<_, K256, MultiEmulationParams> =
            secp256k1_curve.assign_fixed(layouter, K256::generator())?;
        let must_be_pk = secp256k1_curve.msm(layouter, &[holder_sk], &[gen_point])?;
        secp256k1_curve.assert_equal(layouter, &holder_pk, &must_be_pk)?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            secp256k1: true,
            base64: true,
            automaton: true,
            nr_pow2range_cols: 3,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(CredentialProperty)
    }
}

struct Date {
    day: u8,
    month: u8,
    year: u16,
}

impl From<Date> for BigUint {
    fn from(value: Date) -> Self {
        (value.year as u64 * 10_000 + value.month as u64 * 100 + value.day as u64).into()
    }
}

impl CredentialProperty {
    /// Searches for "property": and returns the following `val_len` characters.
    fn get_property(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        body: &[AssignedByte<F>],
        parsed_body: &[AssignedNative<F>],
        marker: usize,
        val_len: usize,
    ) -> Result<Vec<AssignedByte<F>>, Error> {
        let parser = std_lib.parser();
        let parsed_seq: Value<Vec<F>> =
            Value::from_iter(parsed_body.iter().map(|b| b.value().copied()));
        let idx = parsed_seq.map(|parsed_seq| {
            let idx = parsed_seq
                .iter()
                .position(|&m| m == F::from(marker as u64))
                .expect("Property should appear in the credential.");
            F::from(idx as u64)
        });

        let idx = std_lib.assign(layouter, idx)?; // idx will be range-checked in `fetch_bytes`.
        parser.fetch_bytes(layouter, body, &idx, val_len)
    }

    fn assert_str_match(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        str1: &[AssignedByte<F>],
        str2: &[u8],
    ) -> Result<(), Error> {
        assert_eq!(
            str1.len(),
            str2.len(),
            "Compared string lengths must match."
        );
        for (b1, b2) in str1.iter().zip(str2.iter()) {
            std_lib.assert_equal_to_fixed(layouter, b1, *b2)?
        }
        Ok(())
    }

    fn assert_date_before(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        date: &[AssignedByte<F>],
        limit_date: Date,
    ) -> Result<(), Error> {
        let format = (DateFormat::YYYYMMDD, Separator::Sep('-'));
        let date = std_lib.parser().date_to_int(layouter, date, format, None)?;
        std_lib.assert_lower_than_fixed(layouter, &date, &limit_date.into())
    }
    // Creates an CredentialProperty witness from:
    // 1. A JWT encoded credential.
    // 2. The corresponding base64 encoded ECDSA public key.
    fn witness_from_blob(blob: &[u8]) -> (Payload, ECDSASig) {
        let (payload, signature_bytes) = split_blob(blob);

        assert!(verify_credential_sig(PUB_KEY, &payload, &signature_bytes));

        let signature = ECDSASig::from_base64(&signature_bytes).expect("Base64 encoded signature.");

        (
            payload.try_into().expect("Payload of length {PAYLOAD_LEN}"),
            signature,
        )
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let credential_blob = read_credential::<4096>(CRED_PATH).expect("Path to credential file.");

    // Creating proof
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    const K: u32 = 15;

    let kzg_params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(K, rng.clone());

    let witness = CredentialProperty::witness_from_blob(credential_blob.as_slice());
    let holder_sk = SK::from_bytes_be(&HOLDER_SK_BYTES).expect("Valid scalar");

    let witness = (witness.0, holder_sk);
    let circuit = MidnightCircuit::new(
        &CredentialProperty,
        Value::known(()),
        Value::known(witness),
        None,
    );
    let k = k_from_circuit(&circuit);

    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> =
        keygen_vk(&params, &circuit).context("keygen_vk should not fail")?;
    let pk: ProvingKey<Scalar, KZG> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk should not fail")?;

    let mut transcript = CTranscript::init();

    let formatted_instance = CredentialProperty::format_instance(&()).unwrap();
    info!("Public inputs: {:?}", formatted_instance);
    let committed_instance = CredentialProperty::format_committed_instances(&witness);
    let committed_credential = commit_to_instances::<_, KZGCommitmentScheme<_>>(
        &kzg_params,
        vk.get_domain(),
        &committed_instance,
    );
    info!("committed instances: {:?}", committed_instance);

    let nb_committed_instances = 1;
    create_proof(
        &params,
        &pk,
        &[circuit],
        nb_committed_instances,
        &[&[&committed_instance, &formatted_instance]],
        &mut transcript,
        &mut rng,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    let mut invalid_proof = proof.clone();
    let index = 48 * 44 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, KZG, CTranscript>(
        &vk,
        &[&[committed_credential]],
        &[&[&formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    shared_utils::export_plinth(&formatted_instance, Some(committed_credential), &proof)?;
    generate_plinth_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(committed_credential),
    )
    .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&formatted_instance, Some(committed_credential), &proof)?;
    generate_aiken_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(committed_credential),
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
