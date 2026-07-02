use clap::Parser;
use plutus_halo2_verifier_gen::plutus_gen::{EstimateCliArguments, verifier_stats};

fn main() {
    let args = EstimateCliArguments::parse();
    let stats = verifier_stats(
        args.nb_public_inputs,
        usize::from(args.committed_instances),
        args.recursion,
        args.config(),
        &args.chips(),
    );
    println!("{}", stats);
}
