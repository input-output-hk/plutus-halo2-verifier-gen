use anyhow::{Context as _, Result, anyhow};
use blstrs::Scalar;
use std::fs::File;
use std::io::Write;

pub fn export_proof(proof_file: String, proof: Vec<u8>) -> Result<()> {
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

pub fn serialize_proof(proof_file: String, proof: Vec<u8>) -> Result<()> {
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

pub fn export_public_inputs(instances: &[&[&[Scalar]]], output: &mut File) -> Result<()> {
    for instance in instances[0][0].iter() {
        let mut value = instance.to_bytes_le();
        value.reverse();
        output
            .write((hex::encode(value) + "\n").as_bytes())
            .context("Failed to write encoded scalar to the output file")?;
    }

    Ok(())
}
