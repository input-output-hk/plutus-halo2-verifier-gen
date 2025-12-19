use anyhow::{Context as _, Result, bail};
use cardano_serialization_lib::{
    Address, BigNum, ExUnitPrices, LinearFee, PrivateKey, Transaction, TransactionBuilderConfig,
    TransactionBuilderConfigBuilder, TransactionHash, TransactionInput, UnitInterval,
    Value as CardanoValue,
};
use dotenvy::dotenv;
use log::{debug, trace};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Deserialize, Debug)]
pub struct ProtocolParams {
    min_fee_a: u64,
    min_fee_b: u64,
    max_tx_size: u32,
    key_deposit: String,
    pool_deposit: String,
    coins_per_utxo_word: String,
    max_val_size: String,
    min_fee_ref_script_cost_per_byte: u32,
    price_mem: f64,
    price_step: f64,
    cost_models_raw: RawModels,
}

impl ProtocolParams {
    pub(crate) fn get_cost_model(&self) -> Vec<i128> {
        self.cost_models_raw.PlutusV3.clone()
    }
}

#[expect(non_snake_case)]
#[derive(Deserialize, Debug)]
pub struct RawModels {
    pub PlutusV3: Vec<i128>,
}

const BLOCKFROST_API: &str = "https://cardano-preprod.blockfrost.io/api/v0";

pub struct BlockFrostNodeAPI {
    api_key: String,
}

impl BlockFrostNodeAPI {
    pub fn init(api_key: String) -> Self {
        BlockFrostNodeAPI { api_key }
    }
    pub async fn submit_transaction(&self, transaction: &Transaction) -> Result<String> {
        let client = Client::new();
        let blockfrost_url = format!("{}/tx/submit", BLOCKFROST_API);

        let serialized_tx = transaction.to_bytes();

        let response = client
            .post(blockfrost_url)
            .header("project_id", self.api_key.as_str())
            .header("Content-Type", "application/cbor")
            .body(serialized_tx)
            .send()
            .await?;

        if response.status().is_success() {
            let tx_hash: String = response.text().await?;
            Ok(tx_hash.replace("\"", ""))
        } else {
            let error_message = response.text().await?;
            bail!("{error_message}");
        }
    }

    pub async fn wait_for_tx(&self, address: &Address, tx_hash: &str) -> Result<()> {
        while !check_transaction(tx_hash, self.api_key.as_str()).await?
            || self.get_ada_utxos(address).await?.is_empty()
        {
            sleep(Duration::from_millis(5000)).await;
            debug!("still waiting for transaction {:?}", tx_hash);
        }
        Ok(())
    }

    pub async fn fetch_protocol_params(&self) -> Result<ProtocolParams> {
        let url = format!("{}/epochs/latest/parameters", BLOCKFROST_API);

        let client = Client::new();
        let response = client
            .get(&url)
            .header("project_id", self.api_key.as_str())
            .send()
            .await?;

        if !response.status().is_success() {
            bail!("HTTP fail {}", response.status());
        }
        let params: ProtocolParams = response.json().await?;

        Ok(params)
    }

    pub async fn get_ada_utxos(
        &self,
        address: &Address,
    ) -> Result<Vec<(TransactionInput, CardanoValue)>> {
        let pages_to_check = 5;

        let client = Client::new();
        let mut utxos = Vec::new();

        for i in 1..pages_to_check {
            let url = format!(
                "{}/addresses/{}/utxos?order=desc&page={}",
                BLOCKFROST_API,
                address.to_bech32(None)?,
                i
            );

            let response = client
                .get(&url)
                .header("project_id", self.api_key.as_str())
                .send()
                .await?;

            let response = response.json::<serde_json::Value>().await?;

            for utxo in response.as_array().expect("list of UTXOS was not an array") {
                let tx_hash = TransactionHash::from_bytes(hex::decode(
                    utxo["tx_hash"].as_str().expect("tx_hash not found"),
                )?)?;
                let output_index = utxo["output_index"]
                    .as_u64()
                    .expect("output_index not found") as u32;
                let amounts = utxo["amount"].as_array().expect("amount array not found");

                // ignore multi assets as they will not work for paying for mint transactions
                if amounts.len() > 1 {
                    continue;
                }

                let amount: u64 = amounts
                    .first()
                    .expect("amounts are empty")
                    .as_object()
                    .expect("amount is not an JSON object")["quantity"]
                    .as_str()
                    .expect("quantity not found")
                    .parse()?;

                utxos.push((
                    TransactionInput::new(&tx_hash, output_index),
                    CardanoValue::new(&BigNum::from(amount)),
                ));
            }
        }

        trace!("got {} utxos", utxos.len());

        Ok(utxos)
    }
}

async fn check_transaction(tx_hash: &str, api_key: &str) -> Result<bool> {
    let client = Client::new();
    let blockfrost_url = format!("{}/txs/{}", BLOCKFROST_API, tx_hash);

    let response = client
        .get(blockfrost_url.clone())
        .header("project_id", api_key)
        .header("Content-Type", "application/cbor")
        .send()
        .await?;

    if response.status().is_success() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn load_env_vars() -> Result<(String, PrivateKey)> {
    dotenv().context("Failed to read .env file")?;

    let block_frost_api_key: String = env::var("BLOCK_FROST_API_KEY")
        .context("BLOCK_FROST_API_KEY environment variable not set")?;
    let private_key: String =
        env::var("PRIVATE_KEY").context("PRIVATE_KEY environment variable not set")?;
    let private_key: PrivateKey =
        PrivateKey::from_bech32(private_key.as_str()).context("private key is not valid")?;

    Ok((block_frost_api_key, private_key))
}

pub fn to_config(protocol_params: &ProtocolParams) -> Result<TransactionBuilderConfig> {
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
