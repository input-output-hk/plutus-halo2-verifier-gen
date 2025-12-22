use cardano_serialization_lib::{
    Address, BaseAddress, Credential, NetworkInfo, PrivateKey, PublicKey,
};
use dotenvy::dotenv;
use std::env;

fn load_env_vars() -> (String, PrivateKey) {
    dotenv().expect("Failed to read .env file");

    let block_frost_api_key: String =
        env::var("BLOCK_FROST_API_KEY").expect("BLOCK_FROST_API_KEY environment variable not set");
    let private_key: String =
        env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
    let private_key: PrivateKey =
        PrivateKey::from_bech32(private_key.as_str()).expect("private key is not valid");

    (block_frost_api_key, private_key)
}

pub fn to_address(public_key: &PublicKey) -> Address {
    BaseAddress::new(
        NetworkInfo::testnet_preprod().network_id(),
        &Credential::from_keyhash(&public_key.hash()),
        &Credential::from_keyhash(&public_key.hash()),
    )
    .to_address()
}
