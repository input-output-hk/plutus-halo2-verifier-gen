use blstrs::Scalar;
use std::fs::File;
use std::io::Write;

pub fn export_proof(proof_file: String, proof: Vec<u8>) -> Result<(), String> {
    let hex = hex::encode(proof);
    let mut output = File::create(proof_file).map_err(|e| e.to_string())?;
    let _ = output.write(hex.as_bytes());
    Ok(())
}

pub fn serialize_proof(proof_file: String, proof: Vec<u8>) -> Result<(), String> {
    let serialized_proof = serde_json::to_string(&proof).map_err(|e| e.to_string())?;
    let mut output = File::create(proof_file).map_err(|e| e.to_string())?;
    let _ = output.write(serialized_proof.as_bytes());
    Ok(())
}

pub fn export_public_inputs(instances: &[&[&[Scalar]]], output: &mut File) {
    for instance in instances[0][0].iter() {
        let mut value = instance.to_bytes_le();
        value.reverse();
        let _ = output.write((hex::encode(value) + "\n").as_bytes());
    }
}
