mod api;
mod utils;

use crate::api::{BlockFrostNodeAPI, load_env_vars};
use crate::utils::{to_address, to_config};
use cardano_serialization_lib::{
    Address, BigInt, CostModel, Costmdls, Credential, EnterpriseAddress, ExUnits, FixedTransaction,
    Int, Language, MintBuilder, MintWitness, PlutusData, PlutusScript, PlutusScriptSource,
    PlutusScripts, PolicyID, Redeemer, RedeemerTag, Redeemers, ScriptHash, TransactionBuilder,
    TransactionOutputBuilder, TransactionWitnessSet, TxInputsBuilder, Value, Vkeywitnesses,
    make_vkey_witness,
};
use cardano_serialization_lib::{
    AssetName, Assets, BigNum, MultiAsset, PrivateKey, Transaction, TransactionInput,
};
use log::info;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;

#[derive(Deserialize, Debug)]
struct PlutusJson {
    validators: Vec<Validator>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Validator {
    title: String,
    compiled_code: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "trace"));

    let (api_key, private_key) = load_env_vars();

    let file: File = File::open("aiken_halo2/plutus.json")?;
    let reader: BufReader<File> = BufReader::new(file);
    let plutus_json: PlutusJson = serde_json::from_reader(reader)?;

    let validator_title: &str = "verifier.halo2.mint";
    let validator = plutus_json
        .validators
        .iter()
        .find(|v| v.title == validator_title)
        .ok_or(format!("Validator '{}' not found", validator_title))?;

    info!("Found validator: {}", validator.title);

    let cbor_bytes: Vec<u8> = hex::decode(&validator.compiled_code)?;
    // let script_bytes: Vec<u8> = ciborium::from_reader(&cbor_bytes[..])?;

    let smart_contract: PlutusScript = PlutusScript::new_v3(cbor_bytes);
    let script_hash: ScriptHash = PolicyID::from(smart_contract.hash());
    let script_address: EnterpriseAddress =
        EnterpriseAddress::new(0, &Credential::from_scripthash(&script_hash));
    let script_address: Address = script_address.to_address();

    info!("Script Address: {}", script_address.to_bech32(None)?);

    let node_client = BlockFrostNodeAPI::init(api_key);

    let public_key = private_key.to_public();
    let address: Address = to_address(&public_key);
    let utxos = node_client.get_ada_utxos(&address).await?;

    let for_mint = utxos.iter().take(1).cloned().collect();
    let for_collateral = utxos.iter().skip(1).take(3).cloned().collect();

    let transaction = mint(
        &node_client,
        &private_key,
        &smart_contract,
        &AssetName::from_hex("4E466E6F544E466E6F544E466E6F5454")?,
        &address,
        &for_mint,
        &for_collateral,
    )
    .await?;

    let transaction_hash = node_client.submit_transaction(&transaction).await?;

    node_client.wait_for_tx(&address, &transaction_hash).await?;

    Ok(())
}

pub async fn mint(
    node_client: &BlockFrostNodeAPI,
    private_key_paying_for_mint: &PrivateKey,
    script: &PlutusScript,
    asset_name: &AssetName,
    receiving_address: &Address,
    input_utxos: &Vec<(TransactionInput, Value)>,
    collateral_utxos: &Vec<(TransactionInput, Value)>,
) -> Result<Transaction, Box<dyn Error>> {
    let public_key = private_key_paying_for_mint.to_public();
    let address: Address = to_address(&public_key);

    let protocol_params = node_client.fetch_protocol_params().await?;

    let policy_id = PolicyID::from(script.hash());

    // Add inputs from fetched UTXOs
    let mut tx_input_builder = TxInputsBuilder::new();
    for (utxo, amount) in input_utxos {
        tx_input_builder.add_regular_input(&address, &utxo, &amount)?;
    }

    let config = to_config(&protocol_params)?;
    let mut tx_builder = TransactionBuilder::new(&config);
    tx_builder.set_inputs(&tx_input_builder);

    let mut multi_asset = MultiAsset::new();
    let mut assets = Assets::new();
    assets.insert(asset_name, &BigNum::from(1u32));
    multi_asset.insert(&policy_id, &assets);

    let redeemer = Redeemer::new(
        &RedeemerTag::new_mint(),
        &BigNum::zero(),
        &PlutusData::new_integer(&BigInt::from_str("42")?),
        &ExUnits::new(
            &BigNum::from(14_000_000u64),
            &BigNum::from(10_000_000_000u64),
        ),
    );

    let output = TransactionOutputBuilder::new()
        .with_address(receiving_address)
        .next()?
        .with_coin_and_asset(&BigNum::from(15317740u32), &multi_asset)
        .build()?;

    tx_builder.add_output(&output)?;

    let mut mb = MintBuilder::new();
    mb.add_asset(
        &MintWitness::new_plutus_script(&PlutusScriptSource::new(script), &redeemer),
        asset_name,
        &Int::new_i32(1),
    )?;

    tx_builder.set_mint_builder(&mb);
    let mut res = Costmdls::new();

    res.insert(
        &Language::new_plutus_v3(),
        &CostModel::from(protocol_params.cost_models_raw.PlutusV3.clone()),
    );

    let mut tx_input_builder = TxInputsBuilder::new();
    for (utxo, amount) in collateral_utxos {
        tx_input_builder.add_regular_input(&address, &utxo, &amount)?;
    }

    tx_builder.calc_script_data_hash(&res)?;
    tx_builder.set_collateral(&tx_input_builder);
    tx_builder.add_change_if_needed(&address)?;

    let mut witnesses = TransactionWitnessSet::new();

    let tx_body = tx_builder.build()?;
    let fixed_tx = FixedTransaction::new_from_body_bytes(tx_body.to_bytes().as_slice())?;
    let tx_hash = fixed_tx.transaction_hash();
    let vk_witness = &make_vkey_witness(&tx_hash, private_key_paying_for_mint);
    let mut vk = Vkeywitnesses::new();
    vk.add(vk_witness);
    witnesses.set_vkeys(&vk);

    let mut scripts = PlutusScripts::new();
    scripts.add(script);
    witnesses.set_plutus_scripts(&scripts);

    let mut redeemers = Redeemers::new();
    redeemers.add(&redeemer);
    witnesses.set_redeemers(&redeemers);

    let transaction = Transaction::new(&tx_body, &witnesses, None);
    Ok(transaction)
}
