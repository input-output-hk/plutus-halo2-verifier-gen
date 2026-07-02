use clap::Parser;
use plutus_halo2_verifier_gen::plutus_gen::{EstimateCliArguments, estimate_cost};

fn main() {
    let args = EstimateCliArguments::parse();
    estimate_cost(
        args.nb_public_inputs,
        usize::from(args.committed_instances),
        args.recursion,
        args.config(),
        &args.chips(),
    );
}
