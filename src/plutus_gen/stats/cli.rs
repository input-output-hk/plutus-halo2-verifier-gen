use clap::Parser;

use super::{CircuitConfig, SupportedChips};

#[derive(Parser)]
#[command(about = "Estimate Halo2 verifier costs without a full circuit")]
pub struct EstimateCliArguments {
    // Inputs
    #[arg(
        long,
        visible_alias = "pi",
        help_heading = "Proof inputs",
        help = "Number of public inputs."
    )]
    pub nb_public_inputs: usize,

    #[arg(
        long,
        visible_alias = "ci",
        help_heading = "Proof inputs",
        help = "Whether the circuit has committed inputs. [default: false]"
    )]
    pub committed_instances: bool,

    #[arg(
        long,
        visible_alias = "rec",
        help_heading = "Recursion",
        help = "Whether the circuit supports recursion, such as IVC. [default: false]"
    )]
    pub recursion: bool,

    // Chips
    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the Native chip (arithmetic + parallel_add gates)."
    )]
    pub native: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include regular expression parsing."
    )]
    pub automaton: bool,

    #[arg(long, help_heading = "Chips", help = "Include Base64 operations.")]
    pub base64: bool,

    #[arg(long, help_heading = "Chips", help = "Include the SHA256 hash chip.")]
    pub sha256: bool,

    #[arg(long, help_heading = "Chips", help = "Include the SHA512 hash chip.")]
    pub sha512: bool,

    #[arg(long, help_heading = "Chips", help = "Include the Poseidon hash chip.")]
    pub poseidon: bool,

    #[arg(long, help_heading = "Chips", help = "Include the Jubjub curve chip.")]
    pub jubjub: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the BLS12-381 curve chip."
    )]
    pub bls12_381: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the Curve25519 curve chip."
    )]
    pub curve25519: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the secp256k1 curve chip."
    )]
    pub secp256k1: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the secp256r1 curve chip."
    )]
    pub secp256r1: bool,

    #[arg(
        long,
        help_heading = "Chips",
        help = "Include the Poseidon Hash to Jubjub Curve chip."
    )]
    pub hash_to_curve: bool,

    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Number of advice columns.\n The circuit will have max(nb_advice, chips.nb_advice) advice columns."
    )]
    pub nb_advice: usize,

    // Extra configurations
    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Number of extra fixed columns.\n The circuit will have Sum(nb_fixed, nb_selectors, chips.nb_advice) fixed columns."
    )]
    pub nb_fixed: usize,

    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Number of evaluations for extra advice and fixed columns.\n The circuit will have Sum(nb_fixed, nb_selectors, chips.nb_advice) fixed columns."
    )]
    pub nb_evaluations: usize,

    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Number of extra selectors, converted as fixed columns in circuit."
    )]
    pub nb_selectors: usize,

    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Number of extra lookup arguments (added in a new single table)."
    )]
    pub nb_lookups: usize,

    #[arg(
        long,
        help_heading = "Circuit config",
        default_value_t = 0,
        help = "Circuit degree.\n The circuit will have max(circuit_degree, chips.degree, perm.degree, ((nb_lookups + chips.lookup) > 0) * lookups.degree) degree."
    )]
    pub degree: usize,

    #[arg(
        long,
        help_heading = "Circuit config",
        help = "Number of pow2range calls.\n The circuit will have nr_pow2 decomposition lookup arguments or chips.nr_pow2 if none provided."
    )]
    pub nr_pow2: Option<usize>,
}

impl EstimateCliArguments {
    pub fn chips(&self) -> Vec<SupportedChips> {
        let mut chips = Vec::new();
        if self.native {
            chips.push(SupportedChips::Native);
        }
        if self.automaton {
            chips.push(SupportedChips::Automaton);
        }
        if self.base64 {
            chips.push(SupportedChips::Base64);
        }
        if self.jubjub {
            chips.push(SupportedChips::EdwardsJubjub);
        }
        if self.hash_to_curve {
            chips.push(SupportedChips::HashToCurve);
        }
        if self.sha256 {
            chips.push(SupportedChips::Sha256);
        }
        if self.sha512 {
            chips.push(SupportedChips::Sha512);
        }
        if self.poseidon {
            chips.push(SupportedChips::Poseidon);
        }
        if self.bls12_381 {
            chips.push(SupportedChips::WeierstrassBls12381);
        }
        if self.curve25519 {
            chips.push(SupportedChips::Curve25519);
        }
        if self.secp256k1 {
            chips.push(SupportedChips::WeierstrassSecp256k1);
        }
        if self.secp256r1 {
            chips.push(SupportedChips::WeierstrassSecp256r1);
        }
        chips
    }

    pub fn config(&self) -> CircuitConfig {
        CircuitConfig {
            nb_advice: self.nb_advice,
            nb_evaluations: self.nb_evaluations,
            nb_fixed: self.nb_fixed,
            nb_selectors: self.nb_selectors,
            nb_lookups: self.nb_lookups,
            degree: self.degree,
            nr_pow2range_cols: self.nr_pow2,
        }
    }
}
