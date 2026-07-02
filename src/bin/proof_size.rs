use clap::Parser;
use plutus_halo2_verifier_gen::plutus_gen::{EstimateCliArguments, proof_size};

fn main() {
    let args = EstimateCliArguments::parse();
    let size = proof_size(
        args.nb_public_inputs,
        usize::from(args.committed_instances),
        args.recursion,
        args.config(),
        &args.chips(),
    );
    println!("Proof size: {} bytes", size);
}
