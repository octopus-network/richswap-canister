use crate::{
    pool::{self, CoinMeta},
    ExchangeError,
};
use candid::{CandidType, Deserialize, Principal};
use ic_canister_log::log;
use ic_cdk::{api::management_canister::bitcoin::BitcoinNetwork, post_upgrade};
use ic_cdk_macros::{query, update};
use ic_log::*;
use ree_types::{
    bitcoin::psbt::Psbt, exchange_interfaces::*, CoinBalance, CoinId, Intention, Pubkey, Utxo,
};
use rune_indexer::{RuneEntry, Service as RuneIndexer};
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

#[post_upgrade]
pub fn upgrade() {
    crate::migrate::migrate_to_v3();
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

#[update]
pub async fn create(rune_id: CoinId) -> Result<String, ExchangeError> {
    match crate::with_pool_name(&rune_id) {
        Some(addr) => crate::with_pool(&addr, |pool| {
            pool.as_ref()
                .filter(|p| p.states.is_empty())
                .map(|p| p.addr.clone())
                .ok_or(ExchangeError::PoolAlreadyExists)
        }),
        None => {
            let untweaked_pubkey = crate::request_schnorr_key("key_1", rune_id.to_bytes()).await?;
            cfg_if::cfg_if! {
                if #[cfg(feature = "testnet")] {
                    let principal = Principal::from_str(crate::TESTNET_RUNE_INDEXER_CANISTER).unwrap();
                } else {
                    let principal = Principal::from_str(crate::RUNE_INDEXER_CANISTER).unwrap();
                }
            }
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
            crate::create_empty_pool(meta, untweaked_pubkey.clone())
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
pub fn pre_extract_fee(addr: String) -> Result<ExtractFeeOffer, ExchangeError> {
    crate::with_pool(&addr, |p| {
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
    pub user_incomes: u64,
    pub user_share: u128,
    pub total_share: u128,
}

#[query]
pub fn get_lp(addr: String, user_addr: String) -> Result<Liquidity, ExchangeError> {
    crate::with_pool(&addr, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        pool.states
            .last()
            .and_then(|s| {
                Some(Liquidity {
                    user_share: s.lp(&user_addr),
                    user_incomes: s.earning(&user_addr),
                    total_share: s.k,
                })
            })
            .ok_or(ExchangeError::EmptyPool)
    })
}

#[query]
pub fn get_all_lp(addr: String) -> Result<BTreeMap<String, u128>, ExchangeError> {
    crate::with_pool(&addr, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        pool.states
            .last()
            .map(|s| s.lp.clone())
            .ok_or(ExchangeError::EmptyPool)
    })
}

#[query]
pub fn list_pools(from: Option<String>, limit: usize) -> Vec<PoolInfo> {
    let mut pools = crate::get_pools();
    pools.sort_by(|p0, p1| {
        let r0 = p0.states.last().map(|s| s.btc_supply()).unwrap_or_default();
        let r1 = p1.states.last().map(|s| s.btc_supply()).unwrap_or_default();
        r1.cmp(&r0)
    });
    pools
        .iter()
        .skip_while(|p| from.as_ref().map_or(false, |from| &p.addr != from))
        .take(limit as usize + from.as_ref().map_or(0, |_| 1))
        .skip(from.as_ref().map_or(0, |_| 1))
        .map(|p| PoolInfo {
            key: p.pubkey.clone(),
            name: p.meta.symbol.clone(),
            key_derivation_path: vec![p.meta.id.to_bytes()],
            address: p.addr.clone(),
            nonce: p.states.last().map(|s| s.nonce).unwrap_or_default(),
            btc_reserved: p.states.last().map(|s| s.btc_supply()).unwrap_or_default(),
            coin_reserved: p
                .states
                .last()
                .map(|s| {
                    vec![CoinBalance {
                        id: p.meta.id,
                        value: s.rune_supply() as u128,
                    }]
                })
                .unwrap_or(vec![CoinBalance {
                    id: p.meta.id,
                    value: 0,
                }]),
            utxos: p
                .states
                .last()
                .and_then(|s| s.utxo.clone())
                .map(|utxo| vec![utxo])
                .unwrap_or_default(),
            attributes: p.attrs(),
        })
        .collect()
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalOffer {
    pub input: Utxo,
    pub user_outputs: Vec<CoinBalance>,
    pub nonce: u64,
}

#[query]
pub fn pre_withdraw_liquidity(
    pool_addr: String,
    user_addr: String,
    share: u128,
) -> Result<WithdrawalOffer, ExchangeError> {
    crate::with_pool(&pool_addr, |p| {
        let pool = p.as_ref().ok_or(ExchangeError::InvalidPool)?;
        let (btc, rune_output, _) = pool.available_to_withdraw(&user_addr, share)?;
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
    pool_addr: String,
    side: CoinBalance,
) -> Result<LiquidityOffer, ExchangeError> {
    crate::with_pool(&pool_addr, |p| {
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
pub fn pre_swap(id: String, input: CoinBalance) -> Result<SwapOffer, ExchangeError> {
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

/// REE API
#[query]
fn get_minimal_tx_value(_args: GetMinimalTxValueArgs) -> GetMinimalTxValueResponse {
    pool::MIN_BTC_VALUE
}

/// REE API
#[query]
pub fn get_pool_list() -> GetPoolListResponse {
    let pools = crate::get_pools();
    pools
        .iter()
        .map(|p| PoolBasic {
            name: p.meta.symbol.clone(),
            address: p.addr.clone(),
        })
        .collect()
}

/// REE API
#[query]
pub fn get_pool_info(args: GetPoolInfoArgs) -> GetPoolInfoResponse {
    // let pool_key = crate::with_pool_addr(&pool_address)?;
    crate::find_pool(&args.pool_address).map(|p| PoolInfo {
        key: p.pubkey.clone(),
        name: p.meta.symbol.clone(),
        key_derivation_path: vec![p.meta.id.to_bytes()],
        address: p.addr.clone(),
        nonce: p.states.last().map(|s| s.nonce).unwrap_or_default(),
        btc_reserved: p.states.last().map(|s| s.btc_supply()).unwrap_or_default(),
        coin_reserved: p
            .states
            .last()
            .map(|s| {
                vec![CoinBalance {
                    id: p.meta.id,
                    value: s.rune_supply() as u128,
                }]
            })
            .unwrap_or_default(),
        utxos: p
            .states
            .last()
            .and_then(|s| s.utxo.clone())
            .map(|utxo| vec![utxo])
            .unwrap_or_default(),
        attributes: p.attrs(),
    })
}

#[update(guard = "ensure_orchestrator")]
pub fn rollback_tx(args: RollbackTxArgs) -> RollbackTxResponse {
    crate::TX_RECORDS.with_borrow(|m| {
        // Look up the transaction record (both confirmed and unconfirmed)
        let maybe_unconfirmed_record = m.get(&(args.txid.clone(), false));
        let maybe_confirmed_record = m.get(&(args.txid.clone(), true));
        let record = maybe_confirmed_record
            .or(maybe_unconfirmed_record)
            .ok_or("Txid not found")?;
        ic_cdk::println!(
            "rollback txid: {} with pools: {:?}",
            args.txid,
            record.pools
        );
        // Roll back each affected pool to its state before this transaction
        for addr in record.pools.iter() {
            crate::with_pool_mut(addr.clone(), |p| {
                let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
                pool.rollback(args.txid)?;
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    })
}

#[update(guard = "ensure_orchestrator")]
pub fn new_block(args: NewBlockArgs) -> NewBlockResponse {
    // Check for blockchain reorganizations
    match crate::reorg::detect_reorg(BitcoinNetwork::Testnet, args.clone()) {
        Ok(_) => {}
        Err(crate::reorg::Error::DuplicateBlock { height, hash }) => {
            return Err(format!(
                "Duplicate block detected at height {} with hash {}",
                height, hash
            ));
        }
        Err(crate::reorg::Error::Unrecoverable) => {
            return Err("Unrecoverable reorg detected".to_string());
        }
        Err(crate::reorg::Error::Recoverable { height, depth }) => {
            crate::reorg::handle_reorg(height, depth);
        }
    }
    let NewBlockArgs {
        block_height,
        block_hash: _,
        block_timestamp: _,
        confirmed_txids,
    } = args.clone();

    // Store the new block information
    crate::BLOCKS.with_borrow_mut(|m| {
        m.insert(block_height, args);
        ic_cdk::println!("new block {} inserted into blocks", block_height,);
    });

    // Mark transactions as confirmed
    for txid in confirmed_txids {
        crate::TX_RECORDS.with_borrow_mut(|m| {
            if let Some(record) = m.get(&(txid.clone(), false)) {
                m.insert((txid.clone(), true), record.clone());
                ic_cdk::println!("confirm txid: {} with pools: {:?}", txid, record.pools);
            }
        });
    }
    // Calculate the height below which blocks are considered fully confirmed (beyond reorg risk)
    let confirmed_height =
        block_height - crate::reorg::get_max_recoverable_reorg_depth(BitcoinNetwork::Testnet) + 1;

    // Finalize transactions in confirmed blocks
    crate::BLOCKS.with_borrow(|m| {
        m.iter()
            .take_while(|(height, _)| *height <= confirmed_height)
            .for_each(|(height, block_info)| {
                ic_cdk::println!("finalizing txs in block: {}", height);
                block_info.confirmed_txids.iter().for_each(|txid| {
                    crate::TX_RECORDS.with_borrow_mut(|m| {
                        if let Some(record) = m.get(&(txid.clone(), true)) {
                            ic_cdk::println!(
                                "finalize txid: {} with pools: {:?}",
                                txid,
                                record.pools
                            );
                            // Make transaction state permanent in each affected pool
                            record.pools.iter().for_each(|addr| {
                                crate::with_pool_mut(addr.clone(), |p| {
                                    let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
                                    pool.finalize(txid.clone())?;
                                    Ok(Some(pool))
                                })
                                .unwrap();
                            });
                        }
                    });
                });
            });
    });

    // Clean up old block data that's no longer needed
    crate::BLOCKS.with_borrow_mut(|m| {
        let heights_to_remove: Vec<u32> = m
            .iter()
            .take_while(|(height, _)| *height <= confirmed_height)
            .map(|(height, _)| height)
            .collect();
        for height in heights_to_remove {
            ic_cdk::println!("removing block: {}", height);
            m.remove(&height);
        }
    });
    Ok(())
}

/// REE API
#[update(guard = "ensure_orchestrator")]
pub async fn execute_tx(args: ExecuteTxArgs) -> ExecuteTxResponse {
    let ExecuteTxArgs {
        psbt_hex,
        txid,
        intention_set,
        intention_index,
        zero_confirmed_tx_queue_length: _zero_confirmed_tx_queue_length,
    } = args;
    let raw = hex::decode(&psbt_hex).map_err(|_| "invalid psbt".to_string())?;
    let mut psbt = Psbt::deserialize(raw.as_slice()).map_err(|_| "invalid psbt".to_string())?;
    let intention = intention_set.intentions[intention_index as usize].clone();
    let initiator = intention_set.initiator_address.clone();
    let Intention {
        exchange_id: _,
        action: _,
        action_params,
        pool_address,
        nonce,
        pool_utxo_spend,
        pool_utxo_receive,
        input_coins,
        output_coins,
    } = intention;
    // let pool_key = crate::with_pool_addr(&pool_address)
    //     .ok_or(ExchangeError::PoolAddressNotFound.to_string())?;
    let pool = crate::with_pool(&pool_address, |p| p.clone())
        .ok_or(ExchangeError::InvalidPool.to_string())?;
    match intention.action.as_ref() {
        "add_liquidity" => {
            let (new_state, consumed) = pool
                .validate_adding_liquidity(
                    txid,
                    nonce,
                    pool_utxo_spend,
                    pool_utxo_receive,
                    input_coins,
                    output_coins,
                    initiator,
                )
                .map_err(|e| e.to_string())?;
            if let Some(ref utxo) = consumed {
                crate::psbt::sign(&mut psbt, utxo, pool.base_id().to_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            crate::with_pool_mut(pool_address, |p| {
                let mut pool = p.expect("already checked in pre_add_liquidity;qed");
                pool.commit(new_state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "withdraw_liquidity" => {
            let (new_state, consumed) = pool
                .validate_withdrawing_liquidity(
                    txid,
                    nonce,
                    pool_utxo_spend,
                    pool_utxo_receive,
                    action_params
                        .parse()
                        .map_err(|_| "action params \"share\" required")?,
                    input_coins,
                    output_coins,
                    initiator,
                )
                .map_err(|e| e.to_string())?;
            crate::psbt::sign(&mut psbt, &consumed, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(pool_address, |p| {
                let mut pool = p.expect("already checked in available_to_withdraw;qed");
                pool.commit(new_state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "extract_protocol_fee" => {
            let (new_state, consumed) = pool
                .validate_extract_fee(
                    txid,
                    nonce,
                    pool_utxo_spend,
                    pool_utxo_receive,
                    input_coins,
                    output_coins,
                )
                .map_err(|e| e.to_string())?;
            crate::psbt::sign(&mut psbt, &consumed, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(pool_address, |p| {
                let mut pool = p.expect("already checked in extract_fee;qed");
                pool.commit(new_state);
                Ok(Some(pool))
            })
            .map_err(|e| e.to_string())?;
        }
        "swap" => {
            let (new_state, consumed) = pool
                .validate_swap(
                    txid,
                    nonce,
                    pool_utxo_spend,
                    pool_utxo_receive,
                    input_coins,
                    output_coins,
                )
                .map_err(|e| e.to_string())?;
            crate::psbt::sign(&mut psbt, &consumed, pool.base_id().to_bytes())
                .await
                .map_err(|e| e.to_string())?;
            crate::with_pool_mut(pool_address, |p| {
                let mut pool = p.expect("already checked in pre_swap;qed");
                pool.commit(new_state);
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
