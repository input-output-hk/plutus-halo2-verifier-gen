use cardano_serialization_lib::{
    Address, BigNum, PrivateKey, Transaction, TransactionHash, TransactionInput,
    Value as CardanoValue,
};
use dotenvy::dotenv;
use log::trace;
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Deserialize, Debug)]
pub struct ProtocolParams {
    pub min_fee_a: u64,
    pub min_fee_b: u64,
    pub max_tx_size: u32,
    pub key_deposit: String,
    pub pool_deposit: String,
    pub coins_per_utxo_word: String,
    pub max_val_size: String,
    pub min_fee_ref_script_cost_per_byte: u32,
    pub price_mem: f64,
    pub price_step: f64,
    pub cost_models_raw: RawModels,
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
    pub async fn submit_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<String, Box<dyn Error>> {
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
            Err(error_message.into())
        }
    }

    pub async fn wait_for_tx(
        &self,
        address: &Address,
        tx_hash: &str,
    ) -> Result<(), Box<dyn Error>> {
        while !check_transaction(tx_hash, self.api_key.as_str()).await?
            || self.get_ada_utxos(address).await?.is_empty()
        {
            sleep(Duration::from_millis(5000)).await;
            trace!("still waiting for {:?}", tx_hash);
        }
        Ok(())
    }

    pub async fn fetch_protocol_params(&self) -> Result<ProtocolParams, Box<dyn Error>> {
        let url = format!("{}/epochs/latest/parameters", BLOCKFROST_API);

        let client = Client::new();
        let response = client
            .get(&url)
            .header("project_id", self.api_key.as_str())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("HTTP fail {}", response.status()).into());
        }
        let params: ProtocolParams = response.json().await?;

        Ok(params)
    }

    pub async fn get_ada_utxos(
        &self,
        address: &Address,
    ) -> Result<Vec<(TransactionInput, CardanoValue)>, Box<dyn Error>> {
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

            for utxo in response.as_array().unwrap() {
                let tx_hash =
                    TransactionHash::from_bytes(hex::decode(utxo["tx_hash"].as_str().unwrap())?)?;
                let output_index = utxo["output_index"].as_u64().unwrap() as u32;
                let amounts = utxo["amount"].as_array().unwrap();

                // ignore multi assets as they will not work for paying for mint transactions
                if amounts.len() > 1 {
                    continue;
                }

                let amount: u64 = amounts.first().unwrap().as_object().unwrap()["quantity"]
                    .as_str()
                    .unwrap()
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

async fn check_transaction(tx_hash: &str, api_key: &str) -> Result<bool, Box<dyn Error>> {
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

pub fn load_env_vars() -> (String, PrivateKey) {
    dotenv().expect("Failed to read .env file");

    let block_frost_api_key: String =
        env::var("BLOCK_FROST_API_KEY").expect("BLOCK_FROST_API_KEY environment variable not set");
    let private_key: String =
        env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
    let private_key: PrivateKey =
        PrivateKey::from_bech32(private_key.as_str()).expect("private key is not valid");

    (block_frost_api_key, private_key)
}
