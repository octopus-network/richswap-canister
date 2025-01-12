use crate::{
    ic_log::*,
    pool::{CoinMeta, LiquidityPoolWithState, PoolState},
    CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo,
};
use bitcoin::psbt::Psbt;
use candid::{CandidType, Deserialize};
use ic_canister_log::log;
use ic_cdk_macros::{init, post_upgrade, query, update};
use serde::Serialize;
use std::{collections::BTreeMap, str::FromStr};

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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FinalizeTxArgs {
    pub pool_id: Pubkey,
    pub tx_id: Txid,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RollbackTxArgs {
    pub pool_id: Pubkey,
    pub tx_id: Txid,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PoolMeta {
    pub id: Pubkey,
    pub name: String,
    pub address: String,
    pub coins: Vec<CoinId>,
}

#[post_upgrade]
pub fn re_init() {
    //crate::reset_all_pools();
}

#[init]
pub fn init() {}

#[update]
pub fn set_fee_collector(pubkey: Pubkey) {
    crate::set_fee_collector(pubkey);
}

#[query]
pub fn get_fee_collector() -> Pubkey {
    crate::get_fee_collector()
}

#[query]
pub fn list_pools() -> Vec<PoolMeta> {
    crate::get_pools()
        .iter()
        .filter(|p| !p.states.is_empty())
        .map(|p| PoolMeta {
            id: p.pubkey.clone(),
            name: Default::default(),
            address: Default::default(),
            coins: vec![CoinId::btc(), p.meta.id],
        })
        .collect()
}

#[query]
pub fn find_pool(pool_id: Pubkey) -> Option<LiquidityPoolWithState> {
    crate::find_pool(&pool_id).map(|p| p.into())
}

#[update]
pub async fn pre_create(x: CoinBalance, y: CoinBalance) -> Result<Pubkey, ExchangeError> {
    (x.id != y.id)
        .then(|| ())
        .ok_or(ExchangeError::InvalidPool)?;
    (x.id == CoinId::btc() || y.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::BtcRequired)?;
    let rune_id = if x.id == CoinId::btc() { y.id } else { x.id };
    match crate::with_pool_name(&rune_id) {
        Some(pubkey) => crate::with_pool(&pubkey, |pool| {
            pool.as_ref()
                .filter(|p| p.states.is_empty())
                .map(|p| p.pubkey.clone())
                .ok_or(ExchangeError::PoolAlreadyExists)
        }),
        None => {
            let key = crate::request_ecdsa_key("key_1".to_string(), rune_id.to_bytes()).await?;
            let rune = if x.id == CoinId::btc() { y.id } else { x.id };
            // TODO fetch CoinMeta from external
            let meta = CoinMeta {
                id: rune,
                symbol: "RICH".to_string(),
                min_amount: 1,
            };
            crate::create_empty_pool(meta, key.clone())?;
            Ok(key)
        }
    }
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalOffer {
    pub input: Utxo,
    pub user_outputs: Vec<CoinBalance>,
    pub incomes: Option<CoinBalance>,
    pub nonce: u64,
}

#[query]
pub fn pre_withdraw_liquidity(
    pool_id: Pubkey,
    user_pubkey_hash: String,
) -> Result<WithdrawalOffer, ExchangeError> {
    crate::with_pool(&pool_id, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let (btc, rune_output, burn) = pool.available_to_withdraw(&user_pubkey_hash)?;
        let state = pool.states.last().expect("already checked");
        Ok(WithdrawalOffer {
            input: state.utxo.clone().expect("already checked"),
            user_outputs: vec![
                CoinBalance {
                    id: CoinId::btc(),
                    value: btc as u128,
                },
                rune_output,
            ],
            incomes: burn.map(|b| CoinBalance {
                id: CoinId::btc(),
                value: b as u128,
            }),
            nonce: state.nonce,
        })
    })
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityOffer {
    pub inputs: Option<Utxo>,
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
        let another = pool.liquidity_should_add(side)?;
        let state = pool.states.last().expect("already checked");
        Ok(LiquidityOffer {
            inputs: state.utxo.clone(),
            output: another,
            nonce: state.nonce,
        })
    })
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SwapOffer {
    pub input: Utxo,
    pub output: CoinBalance,
    pub nonce: u64,
}

#[query]
pub fn pre_swap(id: Pubkey, input: CoinBalance) -> Result<SwapOffer, ExchangeError> {
    crate::with_pool(&id, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let recent_state = pool.states.last().ok_or(ExchangeError::EmptyPool)?;
        let (offer, _, _) = pool.available_to_swap(input)?;
        Ok(SwapOffer {
            input: recent_state.utxo.clone().expect("already checked"),
            output: offer,
            nonce: recent_state.nonce,
        })
    })
}

// TODO only called by orchestrator
#[update]
pub fn rollback_tx(args: RollbackTxArgs) {
    if let Err(e) = crate::with_pool_mut(&args.pool_id, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.rollback(args.tx_id)?;
        Ok(Some(pool))
    }) {
        log!(ERROR, "Rollback tx {}: {}", e, args.tx_id);
    }
}

// TODO only called by orchestrator
#[update]
pub fn finalize_tx(args: FinalizeTxArgs) {
    if let Err(e) = crate::with_pool_mut(&args.pool_id, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.finalize(args.tx_id)?;
        Ok(Some(pool))
    }) {
        log!(ERROR, "Finalizing tx {}: {}", e, args.tx_id);
    }
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
            let pool_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == rune && o.1 == key.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("output to pool not found".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let user_pubkey_hash = inputs
                .into_iter()
                .find(|i| {
                    i.0.balance.id == CoinId::btc()
                        && i.1 != Some(key.pubkey_hash())
                        && !i.1.is_none()
                })
                .map(|i| i.1.expect("alread checked; qed").to_string())
                .ok_or("couldn't recognize user inputs")?;
            crate::with_pool_mut(&key, |p| {
                let mut pool = p.expect("already checked in pre_create;qed");
                let k = pool_output
                    .balance
                    .value
                    .checked_mul(pool_output.satoshis as u128)
                    .ok_or(ExchangeError::Overflow)?;
                let mut lp = BTreeMap::new();
                let sqrt_k = crate::sqrt(k);
                lp.insert(user_pubkey_hash, sqrt_k);
                let state = PoolState {
                    nonce: 1,
                    txid: tx_id,
                    utxo: Some(pool_output),
                    incomes: 0,
                    k,
                    lp,
                };
                pool.commit(state);
                Ok(Some(pool))
            })
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
            let pool = crate::with_pool(&pool_id, |p| p.clone()).ok_or("pool not found")?;
            let mut state = pool.states.last().expect("already checked;qed").clone();
            (state.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let (btc_delta, rune_delta) = if x.id == CoinId::btc() {
                (x, y)
            } else {
                (y, x)
            };
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let pool_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == rune_delta.id && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("output to pool not found".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let user_pubkey_hash = inputs
                .iter()
                .find(|i| {
                    i.0.balance.id == CoinId::btc()
                        && i.1 != Some(pool.pubkey.pubkey_hash())
                        && !i.1.is_none()
                })
                .map(|i| i.1.expect("alread checked; qed").to_string())
                .ok_or("couldn't recognize user inputs")?;
            let offer = pool.liquidity_should_add(x).map_err(|e| e.to_string())?;
            if offer.value == 0 {
                (pool_output.satoshis as u128 == btc_delta.value)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_output.balance.value == rune_delta.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
            } else {
                // PartialEq tolerance
                let offer_ = pool.liquidity_should_add(y).map_err(|e| e.to_string())?;
                (offer == y || offer_ == x)
                    .then(|| ())
                    .ok_or("inputs mismatch with pre_add_liquidity".to_string())?;
                let pool_input = inputs
                    .iter()
                    .find(|&i| Some(&i.0) == state.utxo.as_ref())
                    .map(|i| i.0.clone())
                    .ok_or("input of pool not found".to_string())?;
                (pool_input.satoshis as u128 + btc_delta.value == pool_output.satoshis as u128)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_input.balance.value + rune_delta.value == pool_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
            };
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            let user_k = btc_delta
                .value
                .checked_mul(rune_delta.value)
                .ok_or(ExchangeError::Overflow.to_string())?;
            let user_share = crate::sqrt(user_k);
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_add_liquidity;qed");
                state.utxo = Some(pool_output);
                state
                    .lp
                    .entry(user_pubkey_hash)
                    .and_modify(|lp| *lp += user_share)
                    .or_insert(user_share);
                state.k = state.rune_supply() * state.btc_supply() as u128;
                state.nonce += 1;
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "withdraw_liquidity" => {
            let pool_id = instruction.pool_id.ok_or("pool_id required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_id, |p| {
                p.as_ref().expect("already checked;qed").clone()
            });
            let mut state = pool
                .states
                .last()
                .ok_or(ExchangeError::EmptyPool.to_string())?
                .clone();
            (state.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let pool_input = inputs
                .iter()
                .find(|&i| Some(&i.0) == state.utxo.as_ref())
                .map(|i| i.0.clone())
                .ok_or("input of pool not found".to_string())?;
            let user_pubkey_hash = inputs
                .into_iter()
                .find(|o| {
                    o.0.balance.id == CoinId::btc()
                        && o.1 != Some(pool.pubkey.pubkey_hash())
                        && o.1.is_some()
                })
                .map(|o| o.1.expect("checked;").to_string())
                .ok_or("couldn't recognize user pubkey")?;
            let (btc_delta, rune_delta, to_burn) = pool
                .available_to_withdraw(&user_pubkey_hash)
                .map_err(|e| e.to_string())?;
            let utxo = if btc_delta + to_burn.unwrap_or_default() == state.satoshis() {
                // all btc consumed, no output to pool
                None
            } else {
                let outputs =
                    crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
                let pool_output = outputs
                    .iter()
                    .find(|&o| o.0.balance.id == rune_delta.id && o.1 == pool.pubkey.pubkey_hash())
                    .map(|o| o.0.clone())
                    .ok_or("output to pool not found".to_string())?;
                (pool_input.satoshis == pool_output.satoshis + btc_delta + to_burn.unwrap_or(0))
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_input.balance.value == pool_output.balance.value + rune_delta.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
                // TODO
                let burn_output = outputs
                    .iter()
                    .find(|&o| o.0.balance.id == CoinId::btc() && o.1 == pool.pubkey.pubkey_hash())
                    .map(|o| o.0.balance.value);
                (to_burn.unwrap_or(0) as u128 == burn_output.unwrap_or(0))
                    .then(|| ())
                    .ok_or("burn output mismatch".to_string())?;
                Some(pool_output)
            };
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in available_to_withdraw;qed");
                state.utxo = utxo;
                state.k = state.rune_supply() * state.btc_supply() as u128;
                if state.utxo.is_none() {
                    state.incomes = 0;
                    state.lp.clear();
                } else {
                    state.lp.remove(&user_pubkey_hash);
                }
                state.nonce += 1;
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "swap" => {
            (instruction.input_coin_balances.len() == 1)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let input = instruction.input_coin_balances[0].clone();
            let pool_id = instruction.pool_id.ok_or("pool_id required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool =
                crate::with_pool(&pool_id, |p| p.clone()).ok_or("pool not found".to_string())?;
            let mut state = pool.states.last().expect("already checked;qed").clone();
            let (offer, _, burn) = pool.available_to_swap(input).map_err(|e| e.to_string())?;
            (state.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let pool_input = inputs
                .iter()
                .find(|&i| state.utxo.as_ref() == Some(&i.0))
                .map(|i| i.0.clone())
                .ok_or("input of pool not found".to_string())?;
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let pool_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == pool.meta.id && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("output to pool not found".to_string())?;
            if input.id == CoinId::btc() {
                let input_btc: u64 = input.value.try_into().expect("BTC amount overflow");
                // pool - rune, + btc
                (pool_input.satoshis + input_btc == pool_output.satoshis)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_input.balance.value - offer.value == pool_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
            } else {
                // pool + rune, - btc
                (pool_input.balance.value + input.value == pool_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
                let output_btc: u64 = offer.value.try_into().expect("BTC amount overflow");
                (pool_input.satoshis - output_btc == pool_output.satoshis)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
            }
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_swap;qed");
                state.utxo = Some(pool_output);
                state.nonce += 1;
                state.incomes += burn;
                pool.commit(state);
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
        "02ad064bd93b6593242c637a54706e780e38ffd12f684e07aa40714a5ae4853a34",
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

#[query(hidden = true)]
fn http_request(
    req: ic_canisters_http_types::HttpRequest,
) -> ic_canisters_http_types::HttpResponse {
    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }
    if req.path() == "/logs" {
        crate::ic_log::do_reply(req)
    } else {
        ic_canisters_http_types::HttpResponseBuilder::not_found().build()
    }
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();
