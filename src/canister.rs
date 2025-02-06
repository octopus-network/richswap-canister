use crate::{
    pool::{CoinMeta, LiquidityPoolWithState},
    ExchangeError, Utxo,
};
use candid::{CandidType, Deserialize, Principal};
use ic_canister_log::log;
use ic_cdk_macros::{query, update};
use ic_log::*;
use ree_types::{bitcoin::psbt::Psbt, exchange_interfaces::*, CoinId, Pubkey, Txid};
use rune_indexer::{RuneEntry, Service as RuneIndexer};
use serde::Serialize;
use std::str::FromStr;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PoolMeta {
    pub id: Pubkey,
    pub name: String,
    pub address: String,
    pub coins: Vec<CoinId>,
}

#[update(guard = "ensure_owner")]
pub fn set_fee_collector(pubkey: Pubkey) {
    crate::set_fee_collector(pubkey);
}

#[update(guard = "ensure_owner")]
pub fn set_orchestrator(principal: Principal) {
    crate::set_orchestrator(principal);
}

#[query]
pub fn get_fee_collector() -> Pubkey {
    crate::get_fee_collector()
}

#[query]
pub fn list_pools(from: Option<Pubkey>, limit: u32) -> Vec<PoolMeta> {
    crate::get_pools()
        .iter()
        .filter(|p| !p.states.is_empty())
        .filter(|p| from.as_ref().map_or(true, |from| p.pubkey > *from))
        .take(limit as usize)
        .map(|p| PoolMeta {
            id: p.pubkey.clone(),
            name: p.meta.symbol.clone(),
            address: p.addr.clone(),
            coins: vec![CoinId::btc(), p.meta.id],
        })
        .collect()
}

#[query]
pub fn find_pool(pool_key: Pubkey) -> Option<LiquidityPoolWithState> {
    crate::find_pool(&pool_key).map(|p| p.into())
}

#[update]
pub async fn create(rune_id: CoinId) -> Result<Pubkey, ExchangeError> {
    match crate::with_pool_name(&rune_id) {
        Some(pubkey) => crate::with_pool(&pubkey, |pool| {
            pool.as_ref()
                .filter(|p| p.states.is_empty())
                .map(|p| p.pubkey.clone())
                .ok_or(ExchangeError::PoolAlreadyExists)
        }),
        None => {
            let untweaked_pubkey = crate::request_schnorr_key("key_1", rune_id.to_bytes()).await?;
            let principal = Principal::from_str(crate::RUNE_INDEXER_CANISTER).unwrap();
            let indexer = RuneIndexer(principal);
            let (entry,): (Option<RuneEntry>,) = indexer
                .get_rune_by_id(rune_id.to_string())
                .await
                .inspect_err(|e| log!(ERROR, "Error fetching rune indexer: {}", e.1))
                .map_err(|_| ExchangeError::FetchRuneIndexerError)?;
            let name = entry
                .map(|e| e.spaced_rune)
                .ok_or(ExchangeError::InvalidRuneId)?;
            let meta = CoinMeta {
                id: rune_id,
                symbol: name,
                min_amount: 1,
            };
            crate::create_empty_pool(meta, untweaked_pubkey.clone())?;
            Ok(untweaked_pubkey)
        }
    }
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtractFeeOffer {
    pub input: Utxo,
    pub output: CoinBalance,
    pub nonce: u64,
}

#[query]
pub fn pre_extract_fee(pool_key: Pubkey) -> Result<ExtractFeeOffer, ExchangeError> {
    crate::with_pool(&pool_key, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let value = pool.available_to_extract()?;
        let state = pool.states.last().ok_or(ExchangeError::EmptyPool)?;
        Ok(ExtractFeeOffer {
            input: state.utxo.clone().ok_or(ExchangeError::EmptyPool)?,
            output: CoinBalance {
                id: CoinId::btc(),
                value: value as u128,
            },
            nonce: state.nonce,
        })
    })
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Liquidity {
    pub btc_supply: u64,
    pub user_share: u128,
    pub sqrt_k: u128,
}

#[query]
pub fn get_lp(pool_key: Pubkey, user_addr: String) -> Result<Liquidity, ExchangeError> {
    crate::with_pool(&pool_key, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        pool.states
            .last()
            .and_then(|s| {
                Some(Liquidity {
                    btc_supply: s.btc_supply(),
                    user_share: s.lp(&user_addr),
                    sqrt_k: crate::sqrt(s.k),
                })
            })
            .ok_or(ExchangeError::EmptyPool)
    })
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalOffer {
    pub input: Utxo,
    pub user_outputs: Vec<CoinBalance>,
    pub nonce: u64,
}

#[query]
pub fn pre_withdraw_liquidity(
    pool_key: Pubkey,
    user_addr: String,
    btc: CoinBalance,
) -> Result<WithdrawalOffer, ExchangeError> {
    (btc.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::InvalidInput)?;
    crate::with_pool(&pool_key, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let (btc, rune_output, _) = pool.available_to_withdraw(&user_addr, btc.value)?;
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
    pool_key: Pubkey,
    side: CoinBalance,
) -> Result<LiquidityOffer, ExchangeError> {
    crate::with_pool(&pool_key, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let another = pool.liquidity_should_add(side)?;
        let state = pool.states.last().clone();
        Ok(LiquidityOffer {
            inputs: state.map(|s| s.utxo.clone()).flatten(),
            output: another,
            nonce: state.map(|s| s.nonce).unwrap_or_default(),
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

#[update(guard = "ensure_orchestrator")]
pub fn rollback_tx(args: RollbackTxArgs) {
    if let Err(e) = crate::with_pool_mut(&args.pool_key, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.rollback(args.tx_id)?;
        Ok(Some(pool))
    }) {
        log!(ERROR, "Rollback tx {}: {}", e, args.tx_id);
    }
}

#[update(guard = "ensure_orchestrator")]
pub fn finalize_tx(args: FinalizeTxArgs) {
    if let Err(e) = crate::with_pool_mut(&args.pool_key, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.finalize(args.tx_id)?;
        Ok(Some(pool))
    }) {
        log!(ERROR, "Finalizing tx {}: {}", e, args.tx_id);
    }
}

#[update(guard = "ensure_orchestrator")]
pub async fn sign_psbt(args: SignPsbtArgs) -> Result<String, String> {
    let SignPsbtArgs {
        psbt_hex,
        tx_id,
        all_instructions,
        instruction_index,
        input_runes,
        output_runes,
        zero_confirmed_tx_count_in_queue: _zero_confirmed_tx_count_in_queue,
    } = args;
    let raw = hex::decode(&psbt_hex).map_err(|_| "invalid psbt".to_string())?;
    let mut psbt = Psbt::deserialize(raw.as_slice()).map_err(|_| "invalid psbt".to_string())?;
    let instruction = all_instructions[instruction_index as usize].clone();
    match instruction.method.as_ref() {
        "add_liquidity" => {
            (instruction.input_coins.len() == 2)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let x = instruction.input_coins[0].coin_balance.clone();
            let y = instruction.input_coins[1].coin_balance.clone();
            let pool_key = instruction
                .pool_key
                .ok_or("pool_key required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_key, |p| p.clone()).ok_or("pool not found")?;
            let mut state = pool.states.last().cloned().unwrap_or_default();
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
                .find(|&o| o.0.balance.id == rune_delta.id && o.1 == pool.addr)
                .map(|o| o.0.clone())
                .ok_or("output to pool not found".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let user_addr = inputs
                .iter()
                .find(|&i| i.0.balance.id == CoinId::btc() && i.1 != pool.addr)
                .map(|i| i.1.clone())
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
            if let Some(ref utxo) = state.utxo {
                crate::psbt::sign(&mut psbt, utxo, pool.base_id().to_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let user_k = btc_delta
                .value
                .checked_mul(rune_delta.value)
                .ok_or(ExchangeError::Overflow.to_string())?;
            let user_share = crate::sqrt(user_k);
            crate::with_pool_mut(&pool_key, |p| {
                let mut pool = p.expect("already checked in pre_add_liquidity;qed");
                state.utxo = Some(pool_output);
                state
                    .lp
                    .entry(user_addr)
                    .and_modify(|lp| *lp += user_share)
                    .or_insert(user_share);
                state.k = state.rune_supply() * state.btc_supply() as u128;
                state.nonce += 1;
                state.id = Some(tx_id);
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "withdraw_liquidity" => {
            let pool_key = instruction
                .pool_key
                .ok_or("pool_key required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_key, |p| {
                p.as_ref().expect("already checked;qed").clone()
            });
            let btc_to_be_withdrawn = instruction
                .output_coins
                .iter()
                .find(|c| c.coin_balance.id == CoinId::btc())
                .map(|c| c.coin_balance.clone())
                .ok_or("btc output not found in output_coins".to_string())?;
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
            let user_addr = inputs
                .into_iter()
                .find(|o| o.0.balance.id == CoinId::btc() && o.1 != pool.addr)
                .map(|o| o.1)
                .ok_or("couldn't recognize user pubkey")?;
            let (btc_delta, rune_delta, new_share) = pool
                .available_to_withdraw(&user_addr, btc_to_be_withdrawn.value)
                .map_err(|e| e.to_string())?;
            let utxo = if btc_delta == state.satoshis() {
                // all btc consumed, no output to pool
                None
            } else {
                let outputs =
                    crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
                let pool_output = outputs
                    .iter()
                    .find(|&o| o.0.balance.id == rune_delta.id && o.1 == pool.addr)
                    .map(|o| o.0.clone())
                    .ok_or("output to pool not found".to_string())?;
                (pool_input.satoshis == pool_output.satoshis + btc_delta)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_input.balance.value == pool_output.balance.value + rune_delta.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
                Some(pool_output)
            };
            let pool_utxo = state
                .utxo
                .as_ref()
                .ok_or(ExchangeError::EmptyPool.to_string())?;
            crate::psbt::sign(&mut psbt, pool_utxo, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_key, |p| {
                let mut pool = p.expect("already checked in available_to_withdraw;qed");
                state.utxo = utxo;
                state.k = state.rune_supply() * state.btc_supply() as u128;
                if state.utxo.is_none() {
                    state.incomes = 0;
                    state.lp.clear();
                } else {
                    state.lp.insert(user_addr, new_share);
                }
                state.nonce += 1;
                state.id = Some(tx_id);
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "extract_fee" => {
            let pool_key = instruction
                .pool_key
                .ok_or("pool_key required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_key, |p| {
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

            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let btc_delta = pool.available_to_extract().map_err(|e| e.to_string())?;
            let fee_pubkey = crate::get_fee_collector();
            let fee_output = outputs
                .iter()
                .find(|&o| o.1 == crate::p2tr_untweaked(&fee_pubkey))
                .map(|o| o.0.clone())
                .ok_or("output of fee collector not found".to_string())?;
            (fee_output.satoshis == btc_delta)
                .then(|| ())
                .ok_or("extracting fee output mismatch")?;
            let utxo = if btc_delta == state.satoshis() {
                // all btc consumed, no output to pool
                None
            } else {
                let pool_output = outputs
                    .iter()
                    .find(|&o| o.1 == pool.addr)
                    .map(|o| o.0.clone())
                    .ok_or("output to pool not found".to_string())?;
                (pool_input.satoshis == pool_output.satoshis + btc_delta)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
                (pool_input.balance.value == pool_output.balance.value)
                    .then(|| ())
                    .ok_or("rune input/output mismatch".to_string())?;
                Some(pool_output)
            };
            let pool_utxo = state
                .utxo
                .as_ref()
                .ok_or(ExchangeError::EmptyPool.to_string())?;
            crate::psbt::sign(&mut psbt, pool_utxo, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_key, |p| {
                let mut pool = p.expect("already checked in extract_fee;qed");
                state.utxo = utxo;
                state.k = state.rune_supply() * state.btc_supply() as u128;
                state.incomes = 0;
                state.nonce += 1;
                state.id = Some(tx_id);
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "swap" => {
            (instruction.input_coins.len() == 1)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let input = instruction.input_coins[0].coin_balance.clone();
            let pool_key = instruction
                .pool_key
                .ok_or("pool_key required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool =
                crate::with_pool(&pool_key, |p| p.clone()).ok_or("pool not found".to_string())?;
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
                .find(|&o| o.0.balance.id == pool.meta.id && o.1 == pool.addr)
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
            let pool_utxo = state
                .utxo
                .as_ref()
                .ok_or(ExchangeError::EmptyPool.to_string())?;
            crate::psbt::sign(&mut psbt, pool_utxo, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_key, |p| {
                let mut pool = p.expect("already checked in pre_swap;qed");
                state.utxo = Some(pool_output);
                state.nonce += 1;
                state.incomes += burn;
                state.id = Some(tx_id);
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
    use ree_types::bitcoin;
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
    let pool_key = CoinId::rune(840000, 846);
    let raw_signature = crate::sign_prehash_with_ecdsa(&sighash, "key_1", pool_key.to_bytes())
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
        ic_log::do_reply(req)
    } else {
        ic_canisters_http_types::HttpResponseBuilder::not_found().build()
    }
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

fn ensure_orchestrator() -> Result<(), String> {
    crate::is_orchestrator(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();
