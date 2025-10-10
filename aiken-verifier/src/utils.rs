use crate::api::ProtocolParams;
use cardano_serialization_lib::{
    Address, BaseAddress, BigNum, Credential, ExUnitPrices, LinearFee, NetworkInfo, PrivateKey,
    PublicKey, TransactionBuilderConfig, TransactionBuilderConfigBuilder, UnitInterval,
};
use dotenvy::dotenv;
use log::trace;
use std::env;
use std::error::Error;

pub fn to_config(
    protocol_params: &ProtocolParams,
) -> Result<TransactionBuilderConfig, Box<dyn Error>> {
    let config = TransactionBuilderConfigBuilder::new()
        .fee_algo(&LinearFee::new(
            &BigNum::from(protocol_params.min_fee_a),
            &BigNum::from(protocol_params.min_fee_b),
        ))
        .pool_deposit(&BigNum::from_str(protocol_params.pool_deposit.as_str())?)
        .key_deposit(&BigNum::from_str(protocol_params.key_deposit.as_str())?)
        .max_value_size(protocol_params.max_val_size.parse::<u32>()?)
        .max_tx_size(protocol_params.max_tx_size)
        .coins_per_utxo_byte(&BigNum::from_str(
            protocol_params.coins_per_utxo_word.as_str(),
        )?)
        .ref_script_coins_per_byte(&UnitInterval::new(
            &BigNum::from(protocol_params.min_fee_ref_script_cost_per_byte),
            &BigNum::from_str("1")?,
        ))
        .ex_unit_prices(&ExUnitPrices::new(
            // those are hardcoded for now
            // "price_mem": 0.0577,
            // "price_step": 0.0000721,
            &UnitInterval::new(&BigNum::from_str("577")?, &BigNum::from_str("10000")?),
            &UnitInterval::new(&BigNum::from_str("721")?, &BigNum::from_str("10000000")?),
        ))
        .build()?;

    trace!("price_mem {}", protocol_params.price_mem);
    trace!("price_step {}", protocol_params.price_step);

    Ok(config)
}

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
