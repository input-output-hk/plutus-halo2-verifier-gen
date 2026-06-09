#[cfg(not(target_arch = "wasm32"))]
use clap::Parser;
#[cfg(not(target_arch = "wasm32"))]
use plutus_halo2_verifier_gen::plutus_gen::{EstimateCliArguments, estimate_cost};

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let args = EstimateCliArguments::parse();
        estimate_cost(
            args.nb_public_inputs,
            usize::from(args.committed_instances),
            args.config(),
            &args.chips(),
        );
    }
}
