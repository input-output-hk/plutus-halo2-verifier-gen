//! Module for proof and pulic input serialization.

use anyhow::{Context as _, Result, anyhow};
use group::Curve;
use midnight_curves::BlsScalar as Scalar;
use midnight_curves::G1Projective;

use std::fs::File;
use std::io::Write;

pub fn export_proof(proof_file: String, proof: &[u8]) -> Result<()> {
    let hex = hex::encode(proof);

    let mut output = File::create(&proof_file)
        .with_context(|| anyhow!("Failed to create file `{proof_file}'"))?;
    output
        .write(hex.as_bytes())
        .with_context(|| anyhow!("Failed to write proof to file `{proof_file}'"))?;
    output
        .flush()
        .with_context(|| anyhow!("Failed to flush to file `{proof_file}'"))?;

    Ok(())
}

pub fn serialize_proof(proof_file: String, proof: &[u8]) -> Result<()> {
    let serialized_proof = serde_json::to_string(&proof)
        .with_context(|| anyhow!("Failed to serialise Proof for `{proof_file}'"))?;

    let mut output = File::create(&proof_file)
        .with_context(|| anyhow!("Failed to create file `{proof_file}'"))?;
    output
        .write(serialized_proof.as_bytes())
        .with_context(|| anyhow!("Failed to write proof to file `{proof_file}'"))?;
    output
        .flush()
        .with_context(|| anyhow!("Failed to flush to file `{proof_file}'"))?;
    Ok(())
}

pub fn export_public_inputs(instance: &[Scalar], output: &mut File) -> Result<()> {
    for instance_i in instance.iter() {
        let value = instance_i.to_bytes_be();
        output
            .write((hex::encode(value) + "\n").as_bytes())
            .context("Failed to write encoded scalar to the output file")?;
    }

    Ok(())
}

pub fn export_committed_inputs(
    com_instances: Option<G1Projective>,
    output: &mut File,
) -> Result<()> {
    if let Some(commit) = com_instances {
        let commit_affine = commit.to_affine();
        let x_coord = commit_affine.x().to_bytes_be();
        let y_coord = commit_affine.y().to_bytes_be();
        output
            .write((hex::encode(x_coord) + "\n").as_bytes())
            .context("Failed to write encoded G1 element's X coordinate to the output file")?;
        output
            .write((hex::encode(y_coord)).as_bytes())
            .context("Failed to write encoded G1 element's Y coordinate to the output file")?;
    };

    Ok(())
}
