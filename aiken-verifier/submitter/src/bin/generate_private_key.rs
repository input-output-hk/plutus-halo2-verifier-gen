use cardano_serialization_lib::PrivateKey;
use submitter::utils::to_address;

fn main() {
    let key = PrivateKey::generate_ed25519().expect("failed to generate alid private key");
    let private_key = key.to_bech32();
    let public_key = key.to_public();
    let address = to_address(&public_key)
        .to_bech32(None)
        .expect("failed to convert address to bech32");
    println!("PrivateKey: {}", private_key);
    println!("PublicKey address: {}", address);
}
