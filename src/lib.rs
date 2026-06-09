pub mod plutus_gen;

#[cfg(not(target_arch = "wasm32"))]
pub mod circuits;
#[cfg(not(target_arch = "wasm32"))]
pub mod kzg_params;

#[cfg(not(target_arch = "wasm32"))]
pub use midnight_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};

#[cfg(target_arch = "wasm32")]
pub mod wasm;
