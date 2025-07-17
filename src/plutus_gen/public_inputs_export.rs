use blstrs::Scalar;
use std::fs::File;
use std::io::Write;
pub fn export_public_inputs(instances: &[&[&[Scalar]]], output: &mut File) {
    for instance in instances[0][0].iter() {
        let mut value = instance.to_bytes_le();
        value.reverse();
        let _ = output.write((hex::encode(value) + "\n").as_bytes());
    }
}
