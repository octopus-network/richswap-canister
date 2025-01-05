use crate::{
    pool::{CoinMeta, LiquidityPoolWithState, Lp, PoolState},
    CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo,
};
use bitcoin::psbt::Psbt;
use candid::{CandidType, Deserialize};
use ic_cdk_macros::{post_upgrade, query, update};
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

#[query]
pub fn list_pools() -> Vec<PoolMeta> {
    crate::get_pools()
        .iter()
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
    pub inputs: Vec<Utxo>,
    pub user_outputs: Vec<CoinBalance>,
    pub incomes: CoinBalance,
    pub nonce: u64,
}

#[query]
pub fn pre_withdraw_liquidity(
    pool_id: Pubkey,
    user_pubkey_hash: String,
) -> Result<WithdrawalOffer, ExchangeError> {
    crate::with_pool(&pool_id, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let (user_outputs, _, incomes) = pool.available_to_withdraw(&user_pubkey_hash)?;
        let state = pool.states.last().expect("already checked");
        let btc = state.btc_utxo.clone();
        let rune = state.rune_utxo.clone();
        Ok(WithdrawalOffer {
            inputs: vec![btc, rune],
            user_outputs,
            incomes,
            nonce: state.nonce,
        })
    })
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
        let another = pool.liquidity_should_add(side)?;
        let state = pool.states.last().expect("already checked");
        let btc = state.btc_utxo.clone();
        let rune = state.rune_utxo.clone();
        Ok(LiquidityOffer {
            inputs: vec![btc, rune],
            output: another,
            nonce: state.nonce,
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
        let recent_state = pool.states.last().ok_or(ExchangeError::EmptyPool)?;
        let (offer, _) = pool.available_to_swap(input)?;
        let btc = recent_state.btc_utxo.clone();
        let rune = recent_state.rune_utxo.clone();
        Ok(SwapOffer {
            inputs: vec![btc, rune],
            output: offer,
            nonce: recent_state.nonce,
        })
    })
}

// TODO only called by orchestrator
#[update]
pub fn rollback_tx(args: RollbackTxArgs) {
    if let Err(_e) = crate::with_pool_mut(&args.pool_id, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.rollback(args.tx_id)?;
        Ok(Some(pool))
    }) {
        // TODO log
    }
}

// TODO only called by orchestrator
#[update]
pub fn finalize_tx(args: FinalizeTxArgs) {
    if let Err(_e) = crate::with_pool_mut(&args.pool_id, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.finalize(args.tx_id)?;
        Ok(Some(pool))
    }) {
        // TODO log
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
                let k = btc_output
                    .balance
                    .value
                    .checked_mul(rune_output.balance.value)
                    .ok_or(ExchangeError::Overflow)?;
                let mut lp = BTreeMap::new();
                let sqrt_k = crate::sqrt(k);
                lp.insert(
                    user_pubkey_hash,
                    Lp {
                        shares: sqrt_k,
                        profit: 0,
                    },
                );
                let state = PoolState {
                    txid: btc_output.txid.clone(),
                    nonce: 1,
                    btc_utxo: btc_output,
                    rune_utxo: rune_output,
                    incomes: 0,
                    untradable: 0,
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
            let offer = pre_add_liquidity(pool_id.clone(), x).map_err(|e| e.to_string())?;
            let offer_ = pre_add_liquidity(pool_id.clone(), y).map_err(|e| e.to_string())?;
            (offer.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            (offer.output == y || offer_.output == x)
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
            let mut state = pool.states.last().expect("already checked;qed").clone();
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let btc_input = inputs
                .iter()
                .find(|&i| i.0 == state.btc_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no btc input of pool".to_string())?;
            let rune_input = inputs
                .iter()
                .find(|&i| i.0 == state.rune_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no rune input of pool".to_string())?;
            let user_pubkey_hash = inputs
                .into_iter()
                .find(|i| {
                    i.0.balance.id == CoinId::btc()
                        && i.1 != Some(pool.pubkey.pubkey_hash())
                        && !i.1.is_none()
                })
                .map(|i| i.1.expect("alread checked; qed").to_string())
                .ok_or("couldn't recognize user inputs")?;
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
            let k = btc_delta
                .value
                .checked_mul(rune_delta.value)
                .ok_or(ExchangeError::Overflow.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_add_liquidity;qed");
                state.btc_utxo = btc_output;
                state.rune_utxo = rune_output;
                let sqrt_k = crate::sqrt(state.k);
                for (_, lp) in state.lp.iter_mut() {
                    let profit = lp
                        .shares
                        .checked_mul(state.incomes)
                        .and_then(|r| r.checked_div(sqrt_k))
                        .ok_or(ExchangeError::Overflow)?;
                    lp.profit += profit;
                }
                state
                    .lp
                    .entry(user_pubkey_hash)
                    .and_modify(|lp| lp.shares += k)
                    .or_insert(Lp {
                        shares: k,
                        profit: 0,
                    });
                // already check overflow in `pre_add_liquidity`
                state.k = state.btc_utxo.balance.value * state.rune_utxo.balance.value;
                state.incomes = 0;
                state.nonce += 1;
                state.txid = tx_id;
                pool.commit(state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "withdraw_liquidity" => {
            (instruction.input_coin_balances.len() == 1)
                .then(|| ())
                .ok_or("invalid input_coin_balances".to_string())?;
            let btc_withdraw_declared = instruction.input_coin_balances[0].clone();
            (btc_withdraw_declared.id == CoinId::btc())
                .then(|| ())
                .ok_or("invalid input_coin_balances")?;
            // let x = instruction.input_coin_balances[0].clone();
            // let y = instruction.input_coin_balances[1].clone();
            // let (btc_delta_declared, rune_delta_declared) = if x.id == CoinId::btc() {
            //     (x, y)
            // } else {
            //     (y, x)
            // };

            let pool_id = instruction.pool_id.ok_or("pool_id required".to_string())?;
            let nonce = instruction.nonce.ok_or("nonce required".to_string())?;
            let pool = crate::with_pool(&pool_id, |p| {
                p.as_ref().expect("already checked;qed").clone()
            });
            let mut state = pool.states.last().expect("already checked;qed").clone();
            (state.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let btc_input = inputs
                .iter()
                .find(|&i| i.0 == state.btc_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no btc input of pool".to_string())?;
            let rune_input = inputs
                .iter()
                .find(|&i| i.0 == state.rune_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no rune input of pool".to_string())?;
            let user_pubkey_hash = inputs
                .into_iter()
                .find(|o| {
                    o.0.balance.id == CoinId::btc()
                        && o.1 != Some(pool.pubkey.pubkey_hash())
                        && o.1.is_some()
                })
                .map(|o| o.1.expect("checked;").to_string())
                .ok_or("couldn't recognize user pubkey")?;
            let outputs =
                crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
            let btc_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == CoinId::btc() && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no btc output of pool".to_string())?;
            let rune_output = outputs
                .iter()
                .find(|&o| o.0.balance.id == pool.meta.id && o.1 == pool.pubkey.pubkey_hash())
                .map(|o| o.0.clone())
                .ok_or("no rune output of pool".to_string())?;

            let (rune_withdraw, profit, pending) = pool
                .available_to_withdraw(&user_pubkey_hash, btc_withdraw_declared)
                .map_err(|e| e.to_string())?;
            (btc_input.balance.value
                == btc_output.balance.value + profit + pending + btc_withdraw_declared.value)
                .then(|| ())
                .ok_or("btc input/output mismatch".to_string())?;
            (rune_input.balance.value == rune_output.balance.value + rune_withdraw.value)
                .then(|| ())
                .ok_or("rune input/output mismatch".to_string())?;
            (rune_input.satoshis == rune_output.satoshis)
                .then(|| ())
                .ok_or("rune input/output satoshis mismatch".to_string())?;
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            let delta_k = btc_withdraw_declared
                .value
                .checked_mul(rune_withdraw.value)
                .ok_or(ExchangeError::Overflow.to_string())?;
            let delta_k = crate::sqrt(delta_k);
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in available_to_withdraw;qed");
                state.btc_utxo = btc_output;
                state.rune_utxo = rune_output;
                let lp = state.lp.remove(&user_pubkey_hash).expect("checked;qed");
                let sqrt_k = crate::sqrt(state.k);
                for (_, lp) in state.lp.iter_mut() {
                    let profit = lp
                        .shares
                        .checked_mul(state.incomes)
                        .and_then(|r| r.checked_div(sqrt_k))
                        .ok_or(ExchangeError::Overflow)?;
                    lp.profit += profit;
                }
                // TODO
                if lp.shares > delta_k {
                    state.lp.insert(
                        user_pubkey_hash,
                        Lp {
                            profit: 0,
                            shares: 0,
                        },
                    );
                }
                // already check overflow in `available_to_withdraw`
                state.k = state.btc_utxo.balance.value * state.rune_utxo.balance.value;
                state.untradable -= pending + profit;
                state.incomes = 0;
                state.nonce += 1;
                state.txid = tx_id;
                pool.commit(state);
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
            let mut state = pool.states.last().expect("already checked;qed").clone();
            let (offer, fee) = pool.available_to_swap(input).map_err(|e| e.to_string())?;
            (state.nonce == nonce)
                .then(|| ())
                .ok_or("pool state expired".to_string())?;
            let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
            let btc_input = inputs
                .iter()
                .find(|&i| i.0 == state.btc_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
                .map(|i| i.0.clone())
                .ok_or("no btc input of pool".to_string())?;
            let rune_input = inputs
                .iter()
                .find(|&i| i.0 == state.rune_utxo && i.1 == Some(pool.pubkey.pubkey_hash()))
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
                (btc_input.balance.value - offer.value == btc_output.balance.value)
                    .then(|| ())
                    .ok_or("btc input/output mismatch".to_string())?;
            }
            crate::psbt::sign(&mut psbt, &pool)
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(&pool_id, |p| {
                let mut pool = p.expect("already checked in pre_swap;qed");
                state.btc_utxo = btc_output;
                state.rune_utxo = rune_output;
                state.nonce += 1;
                state.incomes += fee;
                state.untradable += fee;
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
