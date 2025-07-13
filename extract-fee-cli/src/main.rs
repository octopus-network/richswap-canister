use anyhow::{anyhow, Result};
use bitcoin::{
    absolute::LockTime,
    address::Address,
    psbt::Psbt,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Amount, CompressedPublicKey, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use candid::{encode_args, CandidType, Decode, Deserialize, Encode};
use clap::Parser;
use ic_agent::{export::Principal, identity::AnonymousIdentity, Agent};
use log::error;
use ree_types::*;
use serde::Serialize;
use std::str::FromStr;
use tokio::io::{self as tokio_io, AsyncBufReadExt, AsyncWriteExt};

// mod coin_id;

// Constants
const COIN: u64 = 100_000_000;
const SWAP_CANISTER_ID: &str = "h43eb-lqaaa-aaaao-qjxgq-cai";
const ORCHESTRATOR_CANISTER_ID: &str = "hvyp5-5yaaa-aaaao-qjxha-cai";

const MAINNET_SWAP_CANISTER_ID: &str = "kmwen-yaaaa-aaaar-qam3a-cai";
const MAINNET_ORCHESTRATOR_CANISTER_ID: &str = "kqs64-paaaa-aaaar-qamza-cai";
const NETWORK_URL: &str = "https://ic0.app";

// to HOPE_YOU_GET_RICH
const DEFAULT_FEE_COLLECTOR: &'static str =
    "bc1ptnxf8aal3apeg8r4zysr6k2mhadg833se2dm4nssl7drjlqdh2jqa4tk3p";
// to THIS_IS_FIRST_RUNE
const DEFAULT_TEST_FEE_COLLECTOR: &'static str =
    "tb1pfr420a6qr8t00xwjyfz7x4lg2ppdqnnm3n7gk8x4q4qra93wx88qpam69j";

// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Pool address (where the fee extracting from)
    #[arg(short, long)]
    pool_address: String,

    /// Input private key (for fee UTXO and signing)
    #[arg(short, long)]
    input_priv_key: String,

    /// Network: "testnet" or "mainnet"
    #[arg(short, long, default_value = "testnet")]
    network: String,

    /// Bitcoin RPC URL
    #[arg(long)]
    rpc_url: String,

    /// Bitcoin RPC username
    #[arg(long, default_value = "")]
    rpc_user: String,

    /// Bitcoin RPC password
    #[arg(long, default_value = "")]
    rpc_password: String,

    /// Fallback fee rate in sat/vB to use if RPC call fails
    #[arg(long)]
    fallback_fee_rate: Option<f64>,
}

// UTXO struct that represents a spendable output
// #[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
// struct Utxo {
//     txid: String,
//     vout: u32,
//     sats: u64,
//     maybe_rune: Option<CoinBalance>,
// }

#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
struct UtxoToBeMerge {
    out_rune: CoinBalance,
    out_sats: u64,
    nonce: u64,
    utxos: Vec<Utxo>,
}

#[derive(Debug, Clone, Deserialize, CandidType)]
enum PreExtractResult {
    Ok(ExtractFeeOffer),
    Err(ExchangeError),
}

#[derive(Debug, Clone, Deserialize, CandidType)]
enum PreDonateResult {
    Ok(DonateIntention),
    Err(ExchangeError),
}

// Error handling
#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
enum CliError {
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),

    #[error("Canister error: {0}")]
    CanisterError(String),

    #[error("PSBT creation error: {0}")]
    PsbtError(String),

    #[error("No UTXOs found for fee payment")]
    NoFeeUtxos,

    #[error("Failed to connect to Bitcoin RPC: {0}")]
    RpcConnectionError(String),

    #[error("Fee input too small to cover estimated fee")]
    FeeTooSmall,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Parse command line arguments
    let args = Args::parse();

    // Call async_main directly since we're now in an async context
    async_main(args).await
}

#[derive(Debug, Clone)]
pub struct Config {
    network: Network,
    orchestrator: Principal,
    swap: Principal,
    fee_collector: Address,
}

async fn async_main(args: Args) -> Result<()> {
    // Validate network
    let config = match args.network.to_lowercase().as_str() {
        "testnet" => Ok(Config {
            network: Network::Testnet4,
            orchestrator: Principal::from_text(ORCHESTRATOR_CANISTER_ID).unwrap(),
            swap: Principal::from_text(SWAP_CANISTER_ID).unwrap(),
            fee_collector: Address::from_str(DEFAULT_TEST_FEE_COLLECTOR)
                .unwrap()
                .require_network(Network::Testnet4)
                .unwrap(),
        }),
        "mainnet" => Ok(Config {
            network: Network::Bitcoin,
            orchestrator: Principal::from_text(MAINNET_ORCHESTRATOR_CANISTER_ID).unwrap(),
            swap: Principal::from_text(MAINNET_SWAP_CANISTER_ID).unwrap(),
            fee_collector: Address::from_str(DEFAULT_FEE_COLLECTOR)
                .unwrap()
                .require_network(Network::Bitcoin)
                .unwrap(),
        }),
        _ => Err(anyhow!(CliError::InvalidNetwork(args.network))),
    };
    let config = config.unwrap();

    // Parse private key to derive address
    let private_key = bitcoin::PrivateKey::from_wif(&args.input_priv_key)
        .map_err(|e| anyhow!("Invalid private key: {}", e))?;

    // Make sure the private key network matches the command line network
    if private_key.network != config.network.into() {
        return Err(anyhow!(CliError::InvalidNetwork(format!(
            "Private key network ({:?}) doesn't match specified network ({:?})",
            private_key.network, config.network
        ))));
    }

    // Derive input address from private key
    let secp = Secp256k1::new();
    let input_address = Address::p2wpkh(
        &CompressedPublicKey::try_from(private_key.public_key(&secp)).unwrap(),
        config.network,
    );
    let pool_address = Address::from_str(&args.pool_address)
        .map_err(|e| anyhow!("Invalid pool address: {}", e))?
        .require_network(config.network)?;

    println!("Initializing with network: {:?}", config.network);
    println!("Pool address: {}", args.pool_address);
    println!(
        "Input address (derived from private key): {}",
        input_address
    );

    // Fetch UTXOs for the input address from Bitcoin Core RPC
    println!("Fetching UTXOs for input address from Bitcoin RPC...");
    let fee_utxos = fetch_utxos_from_btc_rpc(&input_address.to_string(), &args.rpc_url).await?;

    // Display UTXOs for fee payment
    println!("Available UTXOs for fee payment (belonging to input address):");
    for (idx, utxo) in fee_utxos.iter().enumerate() {
        println!(
            "[{}] txid: {} vout: {} sats: {}",
            idx, utxo.txid, utxo.vout, utxo.sats
        );
    }

    if fee_utxos.is_empty() {
        error!("No UTXOs found for fee payment. Please ensure the address {} has funds on the network.", input_address);
        return Err(anyhow!(CliError::NoFeeUtxos));
    }

    // Prompt user to select which UTXO to use for fee payment
    let mut stdout = tokio_io::stdout();
    stdout
        .write_all(b"Please select a UTXO to use for fee payment (0-")
        .await?;
    stdout
        .write_all(format!("{}", fee_utxos.len() - 1).as_bytes())
        .await?;
    stdout.write_all(b"): ").await?;
    stdout.flush().await?;

    // Read input from user
    let mut input = String::new();
    let mut stdin = tokio_io::BufReader::new(tokio_io::stdin());
    stdin
        .read_line(&mut input)
        .await
        .map_err(|e| anyhow!("Failed to read from stdin: {}", e))?;
    // Parse input to get the index
    let fee_idx = match input.trim().parse::<usize>() {
        Ok(idx) if idx < fee_utxos.len() => idx,
        Ok(idx) => {
            return Err(anyhow!(CliError::PsbtError(format!(
                "Invalid UTXO index: {}. Must be between 0 and {}",
                idx,
                fee_utxos.len() - 1
            ))));
        }
        Err(e) => {
            return Err(anyhow!(CliError::PsbtError(format!(
                "Failed to parse UTXO index: {}",
                e
            ))));
        }
    };

    let fee_input = fee_utxos[fee_idx].clone();
    if fee_input.sats < 12546 {
        error!("Fee input is too small. Please select a larger UTXO.");
        return Err(anyhow!(CliError::FeeTooSmall));
    }

    println!(
        "Selected fee input: txid: {} vout: {}",
        fee_input.txid, fee_input.vout
    );

    // Fetch UTXOs from canister for the pool address
    println!("Fetching UTXOs from canister for pool address...");
    //
    let (extract, donate) = fetch_utxos_from_canister(
        &args.pool_address,
        &config.fee_collector.to_string(),
        &config.swap,
    )
    .await?;
    // Extract UTXOs and nonce
    // let nonce = canister_utxos.nonce;
    // let pool_utxo = canister_utxos.input.clone();
    // println!(
    //     "Pool UTXO: {}:{}, sats: {}, rune: {:?}",
    //     pool_utxo.txid, pool_utxo.vout, pool_utxo.sats, pool_utxo.maybe_rune
    // );

    // Set fee rate - use command line provided fallback if available, otherwise use defaults
    let feerate_sat_per_vb = if let Some(fallback_rate) = args.fallback_fee_rate {
        println!("Using user-specified fee rate: {} sat/vB", fallback_rate);
        fallback_rate
    } else {
        // Use network-specific default rates
        let is_testnet = config.network == Network::Testnet4;
        if is_testnet {
            3.0
        } else {
            4.0
        }
    };

    // let pool_recv_amount = canister_utxos.out_sats;
    // First, make a dummy PSBT to estimate fee
    let dummy_change_amount = fee_input.sats - 10000u64;
    let dummy_psbt = make_psbt_from_utxos(
        &extract,
        &donate,
        &pool_address,
        &config.fee_collector,
        &input_address,
        &fee_input,
        dummy_change_amount,
    )?;

    // Estimate fee
    let estimated_fee = estimate_psbt_fee(&dummy_psbt, feerate_sat_per_vb)? as u64;

    // Calculate change amount
    let change_amount = fee_input
        .sats
        .checked_sub(estimated_fee)
        .ok_or_else(|| anyhow!(CliError::FeeTooSmall))?;

    // Rebuild PSBT with correct change amount
    let mut psbt = make_psbt_from_utxos(
        &extract,
        &donate,
        &pool_address,
        &config.fee_collector,
        &input_address,
        &fee_input,
        change_amount,
    )?;

    println!("Estimated fee: {} satoshis", estimated_fee);
    println!("Unsigned PSBT (hex format):");
    println!("{}", hex::encode(psbt.serialize()));

    // Display transaction details
    println!("\nTransaction details:");
    println!("- Total inputs: {}", psbt.inputs.len());
    println!("- Total outputs: {}", psbt.unsigned_tx.output.len());
    println!("- Transaction version: {}", psbt.unsigned_tx.version);

    // Show input and output details
    println!("\nInputs:");
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness_utxo) = &input.witness_utxo {
            println!("  Input #{}: {} satoshis", i, witness_utxo.value.to_sat());
        } else {
            println!("  Input #{}: Unknown amount (no witness UTXO)", i);
        }
    }

    println!("\nOutputs:");
    for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
        println!("  Output #{}: {} satoshis", i, output.value.to_sat());
    }

    println!("\nsubmit this psbt?[Y/n]");
    let mut input = String::new();
    let mut stdin = tokio_io::BufReader::new(tokio_io::stdin());
    stdin
        .read_line(&mut input)
        .await
        .map_err(|e| anyhow!("Failed to read from stdin: {}", e))?;
    if input.trim() != "Y" {
        println!("Abort");
        return Ok(());
    }

    // Fee input index (last input)
    sign_input(&mut psbt, 2, &private_key);

    // Submit PSBT to orchestrator
    println!("Submitting PSBT to orchestrator...");

    let response = submit_psbt_to_orchestrator(
        &psbt,
        &extract,
        &donate,
        &config.orchestrator,
        &pool_address,
        &config.fee_collector,
        &input_address,
        estimated_fee,
    )
    .await?;

    println!("Response from orchestrator:");
    println!("{:?}", response);

    Ok(())
}

#[derive(Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct DonateIntention {
    input: Utxo, // the utxo belongs to pool. The client should take this as a input of PSBT
    nonce: u64,  // nonce
    out_rune: CoinBalance, // the rune output to pool
    out_sats: u64, // the btc output to pool
}

#[derive(Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct ExtractFeeOffer {
    pub input: Utxo,
    pub output: CoinBalance,
    pub nonce: u64,
}

#[derive(Debug, Clone, Deserialize, CandidType)]
enum ExtractFeeResult {
    Ok(ExtractFeeOffer),
    Err(ExchangeError),
}

#[derive(Debug, Clone, Deserialize, CandidType)]
enum DonateResult {
    Ok(DonateIntention),
    Err(ExchangeError),
}

async fn fetch_utxos_from_canister(
    extract_from: &str,
    donate_to: &str,
    canister_id: &Principal,
) -> anyhow::Result<(ExtractFeeOffer, DonateIntention)> {
    let agent = Agent::builder()
        .with_url(NETWORK_URL)
        .with_identity(AnonymousIdentity {})
        .build()
        .unwrap();

    let args = encode_args((extract_from.to_string(),)).unwrap();
    let response = agent
        .query(&canister_id, "pre_extract_fee")
        .with_arg(args)
        .call()
        .await
        .unwrap();
    let result = candid::Decode!(&response, PreExtractResult)
        .inspect_err(|e| eprintln!("{:?}", e))
        .unwrap();
    let extract = match result {
        PreExtractResult::Ok(u) => Ok(u),
        PreExtractResult::Err(e) => Err(anyhow::anyhow!("error: {}", e)),
    }?;
    println!("Extracted fee offer: {:?}", extract);
    let args = encode_args((donate_to.to_string(), extract.output.value as u64)).unwrap();
    let response = agent
        .query(&canister_id, "pre_donate")
        .with_arg(args)
        .call()
        .await
        .unwrap();
    let result = candid::Decode!(&response, DonateResult)
        .inspect_err(|e| eprintln!("{:?}", e))
        .unwrap();
    let donate = match result {
        DonateResult::Ok(u) => Ok(u),
        DonateResult::Err(e) => Err(anyhow::anyhow!("error: {}", e)),
    }?;
    println!("Donated intention: {:?}", donate);
    Ok((extract, donate))
}

async fn fetch_utxos_from_btc_rpc(address: &str, rpc_url: &str) -> Result<Vec<Utxo>> {
    let client = reqwest::Client::new();

    #[derive(Serialize)]
    struct RpcRequest {
        jsonrpc: &'static str,
        id: &'static str,
        method: &'static str,
        params: Vec<serde_json::Value>,
    }

    let request = RpcRequest {
        jsonrpc: "1.0",
        id: "curltest",
        method: "scantxoutset",
        params: vec![
            "start".into(),
            serde_json::json!([format!("addr({})", address)]),
        ],
    };
    let builder = client.post(rpc_url);
    #[allow(dead_code, non_snake_case)]
    #[derive(Deserialize, Debug)]
    struct RpcUnspent {
        txid: String,
        vout: u32,
        amount: f64,
        height: u32,
        #[serde(default)]
        desc: String,
        #[serde(default)]
        scriptPubKey: String,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct ScanResult {
        success: bool,
        #[serde(default)]
        unspents: Vec<RpcUnspent>,
        #[serde(default)]
        total_amount: f64,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct RpcResponse {
        result: Option<ScanResult>,
        error: Option<serde_json::Value>,
    }

    let response = builder
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!(CliError::BitcoinRpcError(e.to_string())))?;

    let response = response
        .json::<RpcResponse>()
        .await
        .map_err(|e| anyhow!(CliError::BitcoinRpcError(e.to_string())))?;
    let scan_result = response.result.ok_or_else(|| {
        anyhow!(CliError::BitcoinRpcError(
            "No result in response".to_string()
        ))
    })?;
    if !scan_result.success {
        return Err(anyhow!(CliError::BitcoinRpcError(
            "Scan failed".to_string()
        )));
    }
    if scan_result.unspents.is_empty() {
        return Err(anyhow!(CliError::BitcoinRpcError(
            "No UTXOs found".to_string()
        )));
    }
    let utxos = scan_result
        .unspents
        .into_iter()
        .map(|u| Utxo {
            txid: ree_types::Txid::from_str(&u.txid).unwrap(),
            vout: u.vout,
            sats: (u.amount * COIN as f64) as u64,
            coins: CoinBalances::new(),
        })
        .collect();
    Ok(utxos)
}

// Function for making PSBT from UTXOs
fn make_psbt_from_utxos(
    extract: &ExtractFeeOffer,
    donate: &DonateIntention,
    extract_from: &Address,
    donate_to: &Address,
    fee_address: &Address,
    fee_input: &Utxo,
    change_amount: u64,
) -> Result<Psbt> {
    // Create inputs
    let mut inputs = Vec::with_capacity(3);
    let utxos = vec![
        extract.input.clone(),
        donate.input.clone(),
        fee_input.clone(),
    ];
    for utxo in utxos {
        println!("{}", utxo.txid);
        let txid = Txid::from_str(&utxo.txid.to_string())
            .map_err(|e| anyhow!(CliError::PsbtError(format!("Invalid txid: {}", e))))?;
        // Create outpoint from txid and vout
        // let txid_bytes = hex::decode(&utxo.txid)
        //     .map_err(|e| anyhow!(CliError::PsbtError(format!("Invalid txid hex: {}", e))))?;

        // let mut txid = [0u8; 32];
        // if txid_bytes.len() == 32 {
        //     txid.copy_from_slice(&txid_bytes);
        // } else {
        //     return Err(anyhow!(CliError::PsbtError(format!(
        //         "Invalid txid length: {}",
        //         txid_bytes.len()
        //     ))));
        // }

        // // Create outpoint (reversed because Bitcoin uses little-endian for txids)
        // txid.reverse();
        // // Convert [u8; 32] to Txid by creating a sha256d::Hash first
        // let txid_hash = sha256d::Hash::from_slice(&txid)
        //     .map_err(|e| anyhow!(CliError::PsbtError(format!("Invalid txid hash: {}", e))))?;
        // let txid = Txid::from_raw_hash(txid_hash);
        let outpoint = OutPoint::new(txid, utxo.vout);

        // Create input with sequence number set to 0xffffffff (no RBF)
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX, // Fixed sequence, no RBF
            witness: Witness::new(),
        };
        inputs.push(txin);
    }

    // Create outputs
    let mut outputs = Vec::new();

    // Output 0: extract_from
    outputs.push(TxOut {
        value: Amount::from_sat(extract.input.sats - extract.output.value as u64),
        script_pubkey: extract_from.script_pubkey().clone(),
    });

    // Output 1: donate_to
    outputs.push(TxOut {
        value: Amount::from_sat(donate.out_sats),
        script_pubkey: donate_to.script_pubkey().clone(),
    });

    // Output 2: OP_RETURN for RUNE data (if present)
    let out_rune = vec![
        (0, extract.input.coins.clone()),
        (1, donate.input.coins.clone()),
    ];
    if let Ok(op_return_script) = encode_rune_op_return(out_rune) {
        let op_return_txout = TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        };
        outputs.push(op_return_txout);
    }

    // Output 3: Change output (back to input address)
    outputs.push(TxOut {
        value: Amount::from_sat(change_amount),
        script_pubkey: fee_address.script_pubkey().clone(),
    });

    // Create unsigned transaction
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Create a PSBT from the unsigned transaction
    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| anyhow!(CliError::PsbtError(format!("Failed to create PSBT: {}", e))))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(extract.input.sats),
        script_pubkey: extract_from.script_pubkey().clone(),
    });
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(donate.input.sats),
        script_pubkey: donate_to.script_pubkey().clone(),
    });
    psbt.inputs[2].witness_utxo = Some(TxOut {
        value: Amount::from_sat(fee_input.sats),
        script_pubkey: fee_address.script_pubkey().clone(),
    });
    Ok(psbt)
}

fn sign_input(psbt: &mut Psbt, input_index: usize, sk: &PrivateKey) {
    let secp = Secp256k1::new();
    let sighash_type = EcdsaSighashType::All;
    let mut unsigned_tx = psbt.unsigned_tx.clone();
    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let prev_txout = &psbt.inputs[input_index].witness_utxo.clone().unwrap();
    let sighash = sighasher
        .p2wpkh_signature_hash(
            input_index,
            &prev_txout.script_pubkey,
            prev_txout.value,
            sighash_type,
        )
        .expect("Failed to get sighash");
    //
    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    //
    let msg = Message::from(sighash);
    // let (sk, _) = get_sender_keys(&secp, &owner_address);
    let signature = secp.sign_ecdsa(&msg, &sk.inner);
    //
    // Update the witness stack.
    //
    let signature = bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    };
    let pk = sk.public_key(&secp);
    let witness = Witness::p2wpkh(&signature, &pk.inner);
    psbt.inputs[input_index].final_script_witness = Some(witness);
}

// Function for estimating PSBT fee
fn estimate_psbt_fee(psbt: &Psbt, feerate_sat_per_vb: f64) -> Result<u64> {
    // Estimate virtual size of the final transaction
    // For simplicity, use a formula based on typical transaction size:
    // - Per input: ~68 vB
    // - Per output: ~31 vB
    // - Fixed overhead: ~11 vB

    let num_inputs = psbt.inputs.len();
    let num_outputs = psbt.unsigned_tx.output.len();

    let estimated_vsize = 11 + (num_inputs * 68) + (num_outputs * 31);

    println!(
        "Estimated transaction size: {} vB ({} inputs, {} outputs)",
        estimated_vsize, num_inputs, num_outputs
    );

    // Calculate fee based on feerate
    let estimated_fee = (estimated_vsize as f64 * feerate_sat_per_vb).ceil() as u64;

    println!(
        "Estimated fee at {:.2} sat/vB: {} satoshis",
        feerate_sat_per_vb, estimated_fee
    );

    Ok(estimated_fee)
}

// Function for fetching fee rate from Bitcoin RPC
// This function is now unused, we determine fee rates directly in async_main
// Keep it in case we want to re-enable RPC fee estimation in the future
#[allow(dead_code)]
async fn fetch_fee_rate_from_btc_rpc(
    rpc_url: &str,
    _rpc_user: &str,
    _rpc_password: &str,
) -> Result<f64> {
    // Determine if we're using testnet or mainnet
    let is_testnet = rpc_url.contains("testnet") || rpc_url.contains("test");
    let network = if is_testnet { "testnet" } else { "mainnet" };

    // Default fee rates based on network
    let fee_rate = if is_testnet {
        4.0 // 3 sat/vB for testnet
    } else {
        9.0 // 4 sat/vB for mainnet
    };

    // Simply return the fixed fee rate without making RPC calls
    println!(
        "Using fixed fee rate of {} sat/vB for {} network",
        fee_rate, network
    );
    Ok(fee_rate)
}

// Function to submit PSBT to orchestrator
async fn submit_psbt_to_orchestrator(
    psbt: &Psbt,
    extract: &ExtractFeeOffer,
    donate: &DonateIntention,
    canister_id: &Principal,
    extract_from: &Address,
    donate_to: &Address,
    fee_address: &Address,
    fee: u64,
) -> Result<String> {
    // Serialize PSBT to hex string
    let psbt_hex = hex::encode(psbt.serialize());

    // Create agent to talk to the IC
    let agent = Agent::builder()
        .with_url(NETWORK_URL)
        .with_identity(AnonymousIdentity)
        .build()
        .map_err(|e| {
            anyhow!(CliError::CanisterError(format!(
                "Failed to create agent: {}",
                e
            )))
        })?;
    let txid = psbt.unsigned_tx.compute_txid();
    println!("PSBT txid: {}", txid.to_string());
    // let mut coins = ree_types::CoinBalances::new();
    // coins.add_coin(&intention.out_rune);

    let intention_set = IntentionSet {
        tx_fee_in_sats: fee,
        initiator_address: fee_address.to_string(),
        intentions: vec![
            Intention {
                exchange_id: "RICH_SWAP".to_string(),
                action: "extract_protocol_fee".to_string(),
                action_params: "".to_string(),
                input_coins: vec![],
                output_coins: vec![OutputCoin {
                    coin: CoinBalance {
                        id: CoinId::btc(),
                        value: extract.output.value,
                    },
                    to: donate_to.to_string(),
                }],
                pool_utxo_spent: vec![],
                nonce: extract.nonce,
                pool_utxo_received: vec![],
                pool_address: extract_from.to_string(),
            },
            Intention {
                exchange_id: "RICH_SWAP".to_string(),
                action: "donate".to_string(),
                action_params: "".to_string(),
                input_coins: vec![InputCoin {
                    coin: CoinBalance {
                        id: CoinId::btc(),
                        value: extract.output.value,
                    },
                    from: extract_from.to_string(),
                }],
                output_coins: vec![],
                pool_utxo_spent: vec![],
                nonce: donate.nonce,
                pool_utxo_received: vec![],
                pool_address: donate_to.to_string(),
            },
        ],
    };

    // Create invoke args
    let invoke_args = ree_types::orchestrator_interfaces::InvokeArgs {
        intention_set,
        psbt_hex,
        initiator_utxo_proof: vec![],
    };

    // Encode the invoke_args
    let args = Encode!(&invoke_args).map_err(|e| {
        anyhow!(CliError::CanisterError(format!(
            "Failed to encode arguments: {}",
            e
        )))
    })?;

    // Call invoke on the orchestrator
    let response_bytes = agent
        .update(&canister_id, "invoke")
        .with_arg(args)
        .call_and_wait()
        .await
        .map_err(|e| {
            anyhow!(CliError::CanisterError(format!(
                "Failed to call invoke: {}",
                e
            )))
        })?;

    // Decode response (Result variant)
    let result: Result<String, String> =
        Decode!(&response_bytes, Result<String, String>).map_err(|e| {
            anyhow!(CliError::CanisterError(format!(
                "Failed to decode response: {}",
                e
            )))
        })?;

    // Check if it's Ok or Err variant
    match result {
        Ok(txid) => Ok(txid),
        Err(e) => Err(anyhow!(CliError::CanisterError(e))),
    }
}

pub fn delta(offset: &CoinId, next: &CoinId) -> Option<(u128, u128)> {
    let block = next.block.checked_sub(offset.block)?;

    let tx = if block == 0 {
        next.tx.checked_sub(offset.tx)?
    } else {
        next.tx
    };

    Some((block.into(), tx.into()))
}

// Helper function to encode RUNE OP_RETURN
fn encode_rune_op_return(assignments: Vec<(u32, CoinBalances)>) -> Result<ScriptBuf> {
    use ordinals::varint;
    let mut assignments = assignments
        .into_iter()
        .filter_map(|(i, b)| b.iter().next().cloned().map(|p| (i, p)))
        .collect::<Vec<_>>();
    assignments.sort_by_key(|(_, c)| c.id);
    let mut rune_script_bytes = Vec::<u8>::new();
    varint::encode_to_vec(0, &mut rune_script_bytes); // tag::Body
    let mut prev_id = CoinId::btc();
    for (vout, coin) in assignments {
        let (block, tx) = delta(&prev_id, &coin.id)
            .ok_or_else(|| anyhow!(format!("Invalid coin id: {}", coin.id)))?;
        varint::encode_to_vec(block, &mut rune_script_bytes); // block
        varint::encode_to_vec(tx, &mut rune_script_bytes); // tx
        varint::encode_to_vec(coin.value, &mut rune_script_bytes); // value
        varint::encode_to_vec(vout as u128, &mut rune_script_bytes); // vout
        println!(
            "rune allocation: {} {}:{} -> {}",
            coin.value, coin.id.block, coin.id.tx, vout
        );
        prev_id = coin.id;
    }
    let mut op_return_script = ScriptBuf::default();
    op_return_script.push_opcode(bitcoin::opcodes::all::OP_RETURN);
    op_return_script.push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_13);
    op_return_script.push_instruction(bitcoin::script::Instruction::PushBytes(
        rune_script_bytes.as_slice().try_into().unwrap(),
    ));

    Ok(op_return_script)
}

use thiserror::Error;

#[derive(Debug, Error, Clone, CandidType, Deserialize)]
pub enum ExchangeError {
    #[error("overflow")]
    Overflow,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("invalid pool")]
    InvalidPool,
    #[error("invalid liquidity")]
    InvalidLiquidity,
    #[error("too small funds")]
    TooSmallFunds,
    #[error("lp not found")]
    LpNotFound,
    #[error("fail to fetch rune info")]
    FetchRuneIndexerError,
    #[error("invalid rune id")]
    InvalidRuneId,
    #[error("invalid txid")]
    InvalidTxid,
    #[error("invalid numeric")]
    InvalidNumeric,
    #[error("a pool with the given id already exists")]
    PoolAlreadyExists,
    #[error("the pool has not been initialized or has been removed")]
    EmptyPool,
    #[error("invalid input coin")]
    InvalidInput,
    #[error("couldn't derive a chain key for pool")]
    ChainKeyError,
    #[error("invalid psbt: {0}")]
    InvalidPsbt(String),
    #[error("invalid pool state: {0}")]
    InvalidState(String),
    #[error("invalid sign_psbt args: {0}")]
    InvalidSignPsbtArgs(String),
    #[error("pool state expired, current = {0}")]
    PoolStateExpired(u64),
    #[error("pool address not found")]
    PoolAddressNotFound,
    #[error("fail to fetch utxos from bitcoin canister")]
    FetchBitcoinCanisterError,
    #[error("rune indexer error: {0}")]
    RuneIndexerError(String),
    #[error("no confirmed utxos")]
    NoConfirmedUtxos,
    #[error("bitcoin canister's utxo mismatch")]
    UtxoMismatch,
}
