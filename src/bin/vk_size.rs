use clap::Parser;
use plutus_halo2_verifier_gen::plutus_gen::{EstimateCliArguments, vk_size};

fn main() {
    let args = EstimateCliArguments::parse();
    let size = vk_size(
        args.nb_public_inputs,
        usize::from(args.committed_instances),
        args.recursion,
        args.config(),
        &args.chips(),
    );
    println!("VK size: {} bytes", size);
}
