use std::str::FromStr;

use crate::{
    pool::{CoinMeta, LiquidityPool},
    CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo,
};
use bitcoin::psbt::Psbt;
use candid::{CandidType, Deserialize};
use ic_cdk_macros::{post_upgrade, pre_upgrade, query, update};
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InputRune {
    pub tx_id: Txid,
    pub vout: u32,
    pub btc_amount: u64,
    pub rune_id: Option<CoinId>,
    pub rune_amount: Option<u128>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OutputRune {
    pub btc_amount: u64,
    pub rune_id: Option<CoinId>,
    pub rune_amount: Option<u128>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReeInstruction {
    pub exchange_id: String,
    pub method: String,
    pub pool_id: Option<Pubkey>,
    pub nonce: Option<u64>,
    pub input_coin_balances: Vec<CoinBalance>,
    pub output_coin_balances: Vec<CoinBalance>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignPsbtCallingArgs {
    pub psbt_hex: String,
    pub tx_id: Txid,
    pub instruction: ReeInstruction,
    pub input_runes: Vec<InputRune>,
    pub output_runes: Vec<OutputRune>,
}

#[post_upgrade]
pub fn re_init() {
    crate::reset_all_pools();
}

#[pre_upgrade]
pub fn re_init0() {}

#[query]
pub fn list_pools() -> Vec<LiquidityPool> {
    crate::get_pools()
}

#[query]
pub fn find_pool(pool_id: Pubkey) -> Option<LiquidityPool> {
    crate::find_pool(&pool_id)
}

// TODO
#[update]
pub async fn pre_create(x: CoinBalance, y: CoinBalance) -> Result<Pubkey, ExchangeError> {
    (x.id != y.id)
        .then(|| ())
        .ok_or(ExchangeError::InvalidPool)?;
    (x.id == CoinId::btc() || y.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::BtcRequired)?;
    let rune_id = if x.id == CoinId::btc() { y.id } else { x.id };
    (!crate::has_pool(&rune_id))
        .then(|| ())
        .ok_or(ExchangeError::PoolAlreadyExists)?;
    let key = crate::request_ecdsa_key("key_1".to_string(), rune_id.to_bytes()).await?;
    Ok(key)
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityOffer {
    pub inputs: Vec<Utxo>,
    pub output: CoinBalance,
    pub nonce: u64,
}

#[query]
pub fn pre_add_liquidity(
    pool_id: Pubkey,
    side: CoinBalance,
) -> Result<LiquidityOffer, ExchangeError> {
    crate::with_pool(&pool_id, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let btc = pool.btc_utxo.clone();
        let rune = pool.rune_utxo.clone();
        let another = pool.liquidity_should_add(side)?;
        Ok(LiquidityOffer {
            inputs: vec![btc, rune],
            output: another,
            nonce: pool.nonce,
        })
    })
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SwapOffer {
    pub inputs: Vec<Utxo>,
    pub output: CoinBalance,
    pub nonce: u64,
}

#[query]
pub fn pre_swap(id: Pubkey, input: CoinBalance) -> Result<SwapOffer, ExchangeError> {
    crate::with_pool(&id, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let btc = pool.btc_utxo.clone();
        let rune = pool.rune_utxo.clone();
        let (offer, _) = pool.available_to_swap(input)?;
        Ok(SwapOffer {
            inputs: vec![btc, rune],
            output: offer,
            nonce: pool.nonce,
        })
    })
}

// TODO only called by orchestrator
#[update]
pub async fn sign_psbt(args: SignPsbtCallingArgs) -> Result<String, String> {
    let SignPsbtCallingArgs {
        psbt_hex,
        tx_id,
        instruction,
        input_runes,
        output_runes,
    } = args;
    let raw = hex::decode(&psbt_hex).map_err(|_| "invalid psbt".to_string())?;
    let mut psbt = Psbt::deserialize(raw.as_slice()).map_err(|_| "invalid psbt".to_string())?;
    match instruction.method.as_ref() {
        "create_pool" => {
            (instruction.input_coin_balances.len() == 2)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let x = instruction.input_coin_balances[0].clone();
            let y = instruction.input_coin_balances[1].clone();
            let key = pre_create(x, y).await.map_err(|e| e.to_string())?;
            let rune = if x.id == CoinId::btc() { y.id } else { x.id };
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let btc_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == CoinId::btc() && o.1 == key.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no btc output of pool".to_string())?;
            let rune_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == rune && o.1 == key.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no rune output of pool".to_string())?;
            // TODO fetch CoinMeta from external
            let meta = CoinMeta {
                id: rune,
                symbol: "RICH".to_string(),
                min_amount: 1,
            };
            crate::create_pool(meta, btc_output, rune_output, key)
                .await
                .map_err(|e| e.to_string())?;
        }
        "add_liquidity" => {
            (instruction.input_coin_balances.len() == 2)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let x = instruction.input_coin_balances[0].clone();
            let y = instruction.input_coin_balances[1].clone();
            let pool_id = instruction.pool_id.ok_or("pool_id required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let offer = pre_add_liquidity(pool_id.clone(), x).map_err(|e| e.to_string())?;
            (offer.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            (offer.output == y)
                .then(|| ())
                .ok_or("inputs mismatch with pre_add_liquidity".to_string())?;
            let (btc_delta, rune_delta) = if x.id == CoinId::btc() {
                (x, y)
            } else {
                (y, x)
            };
            let pool = crate::with_pool(&pool_id, |p| {
                p.as_ref().expect("already checked;qed").clone()
            });
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let btc_input = inputs
                .iter()
                .find(|&i| i.0 == pool.btc_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no btc input of pool".to_string())?;
            let rune_input = inputs
                .iter()
                .find(|&i| i.0 == pool.rune_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no rune input of pool".to_string())?;
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let btc_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == CoinId::btc() && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no btc output of pool".to_string())?;
            let rune_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == rune_delta.id && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no rune output of pool".to_string())?;
            (btc_input.balance.value + btc_delta.value == btc_output.balance.value)
                .then(|| ())
                .ok_or("btc input/output mismatch".to_string())?;
            (rune_input.balance.value + rune_delta.value == rune_output.balance.value)
                .then(|| ())
                .ok_or("rune input/output mismatch".to_string())?;
            (rune_input.satoshis == rune_output.satoshis)
                .then(|| ())
                .ok_or("rune input/output satoshis mismatch".to_string())?;
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_add_liquidity;qed");
                pool.btc_utxo = btc_output;
                pool.rune_utxo = rune_output;
                // already check overflow in `pre_add_liquidity`
                pool.k = pool.btc_utxo.balance.value * pool.rune_utxo.balance.value;
                pool.nonce += 1;
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "swap" => {
            (!instruction.input_coin_balances.is_empty())
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let input = instruction.input_coin_balances[0].clone();
            let pool_id = instruction.pool_id.ok_or("pool_id required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_id, |p| {
                p.as_ref().expect("already checked;qed").clone()
            });
            let (offer, _) = pool.available_to_swap(input).map_err(|e| e.to_string())?;
            (pool.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let btc_input = inputs
                .iter()
                .find(|&i| i.0 == pool.btc_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no btc input of pool".to_string())?;
            let rune_input = inputs
                .iter()
                .find(|&i| i.0 == pool.rune_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no rune input of pool".to_string())?;
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let btc_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == CoinId::btc() && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no btc output of pool".to_string())?;
            let rune_output = outputs
                .iter()
                .find(|&o| {
                    o.0.balance.id == rune_input.balance.id && o.1 == pool.pubkey.pubkey_hash()
                })
                .map(|o| o.0.clone())
                .ok_or("no rune output of pool".to_string())?;
            if input.id == CoinId::btc() {
                // pool - rune, + btc
                // TODO fee
                (btc_input.balance.value + input.value == btc_output.balance.value)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (rune_input.balance.value - offer.value == rune_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
            } else {
                // pool + rune, - btc
                (rune_input.balance.value + input.value == rune_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
                // TODO fee
                (btc_input.balance.value - offer.value == btc_output.balance.value)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
            }
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_swap;qed");
                pool.btc_utxo = btc_output;
                pool.rune_utxo = rune_output;
                pool.nonce += 1;
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        _ => {
            return Err("invalid method".to_string());
        }
    }
    Ok(psbt.serialize_hex())
}

#[update]
pub async fn manually_transfer(txid: Txid, vout: u32, satoshis: u64) -> Option<String> {
    let mut inputs = vec![];
    inputs.push(bitcoin::TxIn {
        previous_output: bitcoin::OutPoint {
            txid: txid.into(),
            vout,
        },
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: bitcoin::Witness::new(),
    });
    let sender_pubkey = bitcoin::PublicKey::from_str(
        "021774b3f1c2d9f8e51529eda4a54624e2f067826b42281fb5b9a9b40fd4a967e9",
    )
    .unwrap();

    let rev_pubkey = bitcoin::PublicKey::from_str(
        "0294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a",
    )
    .unwrap();
    let mut outputs = vec![];
    let all = bitcoin::Amount::from_sat(satoshis - 350);
    outputs.push(bitcoin::TxOut {
        value: all,
        script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(&rev_pubkey.wpubkey_hash().ok()?),
    });

    let mut unsigned = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    let sighash_type = bitcoin::sighash::EcdsaSighashType::All;
    let mut sighasher = bitcoin::sighash::SighashCache::new(&mut unsigned);
    let sighash = sighasher
        .p2wpkh_signature_hash(
            0,
            &bitcoin::ScriptBuf::new_p2wpkh(&sender_pubkey.wpubkey_hash().ok()?),
            bitcoin::Amount::from_sat(satoshis),
            sighash_type,
        )
        .expect("failed to create sighash");
    let pool_id = CoinId::rune(840000, 846);
    let raw_signature =
        crate::sign_prehash_with_ecdsa(&sighash, "key_1".to_string(), pool_id.to_bytes())
            .await
            .ok()?;
    let signature = bitcoin::ecdsa::Signature {
        signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&raw_signature)
            .expect("assert: chain-key signature is 64-bytes compact format"),
        sighash_type,
    };
    *sighasher.witness_mut(0).unwrap() = bitcoin::Witness::p2wpkh(
        &signature,
        &bitcoin::secp256k1::PublicKey::from_slice(&sender_pubkey.to_bytes())
            .expect("assert: pool pubkey is generated by ICP"),
    );
    let tx = sighasher.into_transaction();

    let tx = bitcoin::consensus::encode::serialize(&tx);
    Some(hex::encode(tx))
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();

#[test]
pub fn debug_psbt() {
    let psbt_hex = "70736274ff0100fd1801020000000349be4ee3213f275e720244eb30c6be478e4858b53ea5e554783226d7d0016def0100000000ffffffffa6000363e84f15b0551094e60454206aa6cdbabe982a065030201b1b187a19520000000000ffffffff7fbe48d7e08c8c74f37dbc3bf9e8e8518f98529dd75f3432bde7a00b9e00f5cd0200000000ffffffff0500000000000000000e6a5d0b00c0a233ce0695b58e01022202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db053119000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a289a010000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000001011ff5b8010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086c02483045022100a8eeaf6364f986bda4d5cd2a913d7abceb5e6041b96c077ac01ed8f68d2e81b702204d098d548f07e94c01a19245e6cf69753cdf9d879563827bc4052c1401dff49a01210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001011f8813000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db050001011f2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000000";
    let psbt_bytes = hex::decode(&psbt_hex).unwrap();
    let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
    psbt.inputs.iter().for_each(|input| {
        println!("{:?}\n", input);
    });
    psbt.unsigned_tx.input.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.outputs.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.unsigned_tx.output.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
}
