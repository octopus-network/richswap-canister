mod canister;
mod migrate;
mod pool;
mod psbt;
mod reorg;

use crate::pool::{CoinMeta, LiquidityPool, DEFAULT_BURN_RATE, DEFAULT_FEE_RATE};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::schnorr::{
    self, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument,
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    Cell, DefaultMemoryImpl, StableBTreeMap,
};
use ordinals::{Artifact, Edict, Runestone};
use ree_types::{
    bitcoin::{key::TapTweak, secp256k1::Secp256k1, Address, Network},
    exchange_interfaces::*,
    CoinBalance, CoinId, Pubkey, TxRecord, Txid, Utxo,
};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str::FromStr;
use thiserror::Error;

pub const MIN_RESERVED_SATOSHIS: u64 = 546;
pub const RUNE_INDEXER_CANISTER: &'static str = "kzrva-ziaaa-aaaar-qamyq-cai";
pub const TESTNET_RUNE_INDEXER_CANISTER: &'static str = "f2dwm-caaaa-aaaao-qjxlq-cai";
pub const BTC_CANISTER: &'static str = "ghsi2-tqaaa-aaaan-aaaca-cai";
pub const TESTNET_BTC_CANISTER: &'static str = "g4xu7-jiaaa-aaaan-aaaaq-cai";
pub const ORCHESTRATOR_CANISTER: &'static str = "kqs64-paaaa-aaaar-qamza-cai";
pub const DEFAULT_FEE_COLLECTOR: &'static str =
    "269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9";
pub const TESTNET_GUARDIAN_PRINCIPAL: &'static str =
    "65xmn-zk27d-l4li6-t6jbb-w42dk-k37sl-tthdg-uaevy-ucb34-uu66z-6qe";
pub const GUARDIAN_PRINCIPAL: &'static str =
    "v5md3-vs7qy-se4kd-gzd2u-mi225-76rva-rt2ci-ibb2p-petro-2y7aj-hae";

#[derive(Eq, PartialEq, Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct Output {
    pub balance: CoinBalance,
    pub pubkey: Pubkey,
}

#[derive(Debug, Error, CandidType)]
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
    #[error("exchange paused")]
    Paused,
    #[error("price impact limit exceeded")]
    PriceImpactLimitExceeded,
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

const _POOL_TOKENS_MEMORY_ID_V2: MemoryId = MemoryId::new(1);
const FEE_COLLECTOR_MEMORY_ID: MemoryId = MemoryId::new(2);
const ORCHESTRATOR_MEMORY_ID: MemoryId = MemoryId::new(3);
// deprecated
const _POOL_ADDR_MEMORY_ID: MemoryId = MemoryId::new(4);
const POOLS_MEMORY_ID_V2: MemoryId = MemoryId::new(5);
// the v3 is token -> addr
const POOL_TOKENS_MEMORY_ID: MemoryId = MemoryId::new(7);
// the v3 is addr -> pool, notice: 6 is deprecated in the testnet
const POOLS_MEMORY_ID: MemoryId = MemoryId::new(10);

const BLOCKS_ID: MemoryId = MemoryId::new(8);
const TX_RECORDS_ID: MemoryId = MemoryId::new(9);
const WHITELIST_ID: MemoryId = MemoryId::new(11);
const PAUSED_ID: MemoryId = MemoryId::new(12);

thread_local! {
    static MEMORY: RefCell<Option<DefaultMemoryImpl>> = RefCell::new(Some(DefaultMemoryImpl::default()));

    static MEMORY_MANAGER: RefCell<Option<MemoryManager<DefaultMemoryImpl>>> =
        RefCell::new(Some(MemoryManager::init(MEMORY.with(|m| m.borrow().clone().unwrap()))));

    static POOLS_V2: RefCell<StableBTreeMap<Pubkey, crate::migrate::LiquidityPoolV2, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOLS_MEMORY_ID_V2))));

    pub(crate) static POOLS: RefCell<StableBTreeMap<String, LiquidityPool, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOLS_MEMORY_ID))));

    static _POOL_TOKENS_V2: RefCell<StableBTreeMap<CoinId, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(_POOL_TOKENS_MEMORY_ID_V2))));

    pub(crate) static POOL_TOKENS: RefCell<StableBTreeMap<CoinId, String, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOL_TOKENS_MEMORY_ID))));

    static _POOL_ADDR_DEPRECATED: RefCell<StableBTreeMap<String, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(_POOL_ADDR_MEMORY_ID))));

    static FEE_COLLECTOR: RefCell<Cell<Pubkey, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(FEE_COLLECTOR_MEMORY_ID)), Pubkey::from_str(DEFAULT_FEE_COLLECTOR).expect("invalid pubkey: fee collector"))
                     .expect("fail to init a StableCell"));

    static ORCHESTRATOR: RefCell<Cell<Principal, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(ORCHESTRATOR_MEMORY_ID)), Principal::from_str(ORCHESTRATOR_CANISTER).expect("invalid principal: orchestrator"))
                     .expect("fail to init a StableCell"));

    pub(crate) static BLOCKS: RefCell<StableBTreeMap<u32, NewBlockInfo, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(BLOCKS_ID))));

    pub(crate) static TX_RECORDS: RefCell<StableBTreeMap<(Txid, bool), TxRecord, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(TX_RECORDS_ID))));

    pub(crate) static WHITELIST: RefCell<StableBTreeMap<String, (), Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(WHITELIST_ID))));

    pub(crate) static PAUSED: RefCell<Cell<bool, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(PAUSED_ID)), false).expect("fail to init a StableCell"));
}

fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<DefaultMemoryImpl>) -> R) -> R {
    MEMORY_MANAGER.with(|cell| {
        f(cell
            .borrow()
            .as_ref()
            .expect("memory manager not initialized"))
    })
}

pub(crate) fn get_tx_affected(txid: Txid) -> Option<TxRecord> {
    let confirmed = TX_RECORDS.with_borrow(|r| r.get(&(txid, true)).clone());
    let unconfirmed = TX_RECORDS.with_borrow(|r| r.get(&(txid, false)).clone());
    unconfirmed.or(confirmed)
}

pub(crate) fn get_block(block_height: u32) -> Option<NewBlockInfo> {
    BLOCKS.with_borrow(|b| b.get(&block_height).clone())
}

pub(crate) fn get_max_block() -> Option<NewBlockInfo> {
    BLOCKS.with_borrow(|b| b.last_key_value().map(|(_, v)| v.clone()))
}

pub(crate) fn with_pool<F, R>(id: &String, f: F) -> R
where
    F: Fn(&Option<LiquidityPool>) -> R,
{
    POOLS.with_borrow(|p| {
        let pool = p.get(id);
        f(&pool)
    })
}

pub(crate) fn with_pool_mut<F>(id: String, f: F) -> Result<(), ExchangeError>
where
    F: FnOnce(Option<LiquidityPool>) -> Result<Option<LiquidityPool>, ExchangeError>,
{
    POOLS.with_borrow_mut(|p| {
        let pool = f(p.get(&id));
        match pool {
            Ok(Some(pool)) => {
                p.insert(id.clone(), pool);
                Ok(())
            }
            Ok(None) => {
                p.remove(&id);
                Ok(())
            }
            Err(e) => Err(e),
        }
    })
}

pub(crate) fn get_pools() -> Vec<LiquidityPool> {
    POOLS.with_borrow(|p| p.iter().map(|p| p.1.clone()).collect::<Vec<_>>())
}

pub(crate) fn find_pool(addr: &String) -> Option<LiquidityPool> {
    with_pool(addr, |p| p.clone())
}

pub(crate) fn has_pool(id: &CoinId) -> bool {
    POOL_TOKENS.with_borrow(|p| p.contains_key(&id))
}

pub(crate) fn with_pool_name(id: &CoinId) -> Option<String> {
    POOL_TOKENS.with_borrow(|p| p.get(&id).clone())
}

// pub(crate) fn with_pool_addr(addr: &String) -> Option<Pubkey> {
//     POOL_ADDR.with_borrow(|p| p.get(addr))
// }

pub(crate) fn tweak_pubkey_with_empty(untweaked: Pubkey) -> Pubkey {
    let secp = Secp256k1::new();
    let (tweaked, _) = untweaked.to_x_only_public_key().tap_tweak(&secp, None);
    let raw = tweaked.serialize().to_vec();
    Pubkey::from_raw([&[0x00], &raw[..]].concat()).expect("tweaked 33bytes; qed")
}

pub(crate) async fn request_schnorr_key(
    key_name: impl ToString,
    path: Vec<u8>,
) -> Result<Pubkey, ExchangeError> {
    let arg = SchnorrPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![path],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_name.to_string(),
        },
    };
    let res = schnorr::schnorr_public_key(arg)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    let mut raw = res.0.public_key.to_vec();
    raw[0] = 0x00;
    let pubkey = Pubkey::from_raw(raw).expect("management api error: invalid pubkey");
    Ok(pubkey)
}

pub(crate) async fn sign_prehash_with_schnorr(
    digest: impl AsRef<[u8; 32]>,
    key_name: impl ToString,
    path: Vec<u8>,
) -> Result<Vec<u8>, ExchangeError> {
    let signature = chain_key::schnorr_sign(digest.as_ref().to_vec(), path, key_name, None)
        .await
        .map_err(|_| ExchangeError::ChainKeyError)?;
    Ok(signature)
}

pub(crate) fn create_empty_pool(
    meta: CoinMeta,
    untweaked: Pubkey,
) -> Result<String, ExchangeError> {
    if has_pool(&meta.id) {
        return Err(ExchangeError::PoolAlreadyExists);
    }
    let id = meta.id;
    let pool =
        LiquidityPool::new_empty(meta, DEFAULT_FEE_RATE, DEFAULT_BURN_RATE, untweaked.clone())
            .expect("didn't set fee rate");
    let addr = pool.addr.clone();
    POOL_TOKENS.with_borrow_mut(|l| {
        l.insert(id, addr.clone());
        POOLS.with_borrow_mut(|p| {
            p.insert(addr.clone(), pool);
        });
    });
    Ok(addr)
}

pub(crate) fn p2tr_untweaked(pubkey: &Pubkey) -> String {
    let untweaked = pubkey.to_x_only_public_key();
    cfg_if::cfg_if! {
        if #[cfg(feature = "testnet")] {
            let address = Address::p2tr(&Secp256k1::new(), untweaked, None, Network::Testnet4);
        } else {
            let address = Address::p2tr(&Secp256k1::new(), untweaked, None, Network::Bitcoin);
        }
    }
    address.to_string()
}

pub(crate) fn ensure_online() -> Result<(), ExchangeError> {
    PAUSED
        .with(|p| !*p.borrow().get())
        .then(|| ())
        .ok_or(ExchangeError::Paused)
}

pub(crate) fn get_fee_collector() -> Pubkey {
    FEE_COLLECTOR.with(|f| f.borrow().get().clone())
}

pub(crate) fn set_fee_collector(pubkey: Pubkey) {
    let _ = FEE_COLLECTOR.with(|f| f.borrow_mut().set(pubkey));
}

pub(crate) fn is_orchestrator(principal: &Principal) -> bool {
    ORCHESTRATOR.with(|o| o.borrow().get() == principal)
}

pub(crate) fn is_guardian(principal: &Principal) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "testnet")] {
            principal == &Principal::from_text(TESTNET_GUARDIAN_PRINCIPAL).unwrap() ||
                principal == &Principal::from_text("kcbkg-xe6mr-ahw5e-vtnl5-jzrlt-peuis-j4fuh-64oqd-a36ns-vh4z3-xae").unwrap()
        } else {
            principal == &Principal::from_text(GUARDIAN_PRINCIPAL).unwrap()
        }
    }
}

pub(crate) fn set_orchestrator(principal: Principal) {
    let _ = ORCHESTRATOR.with(|o| o.borrow_mut().set(principal));
}

/// sqrt(x) * sqrt(x) <= x
pub(crate) fn sqrt(x: u128) -> u128 {
    x.isqrt()
}

pub(crate) fn calculate_merge_utxos(utxos: &[Utxo], rune_id: CoinId) -> (u64, CoinBalance) {
    let mut sats = 0;
    let mut balance = CoinBalance {
        id: rune_id,
        value: 0,
    };
    for utxo in utxos {
        if let Some(rune) = &utxo.maybe_rune {
            if rune.id == rune_id {
                balance.value += rune.value;
            }
        }
        sats += utxo.sats;
    }
    (sats, balance)
}

pub(crate) async fn get_untracked_utxos_of_pool(
    pool: &LiquidityPool,
) -> Result<Vec<Utxo>, ExchangeError> {
    let confirmed = get_confirmed_utxos_of_pool(pool).await?;
    if confirmed.is_empty() || confirmed.len() == 1 {
        return Err(ExchangeError::NoConfirmedUtxos);
    }
    // TODO if some tx is confirming based on the tracking UTXO of pool, the mempool will reject this
    Ok(confirmed.values().cloned().collect::<Vec<_>>())
}

/// fetch utxos of pool from btc canister & rune indexer
pub(crate) async fn get_confirmed_utxos_of_pool(
    pool: &LiquidityPool,
) -> Result<BTreeMap<String, Utxo>, ExchangeError> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "testnet")] {
            let (btc_canister_id, indexer_id, network) =
            (Principal::from_text(TESTNET_BTC_CANISTER).unwrap(), Principal::from_text(TESTNET_RUNE_INDEXER_CANISTER).unwrap(), bitcoin_canister::Network::Testnet);
        } else {
            let (btc_canister_id, indexer_id, network) =
            (Principal::from_text(BTC_CANISTER).unwrap(), Principal::from_text(RUNE_INDEXER_CANISTER).unwrap(), bitcoin_canister::Network::Mainnet);
        }
    }
    let btc_canister = bitcoin_canister::Service(btc_canister_id);
    let indexer = rune_indexer::Service(indexer_id);
    let (response,): (bitcoin_canister::GetUtxosResponse,) = btc_canister
        .bitcoin_get_utxos(bitcoin_canister::GetUtxosRequest {
            network,
            filter: Some(bitcoin_canister::GetUtxosRequestFilterInner::MinConfirmations(1)),
            address: pool.addr.clone(),
        })
        .await
        .inspect_err(|e| ic_cdk::println!("{:?}", e.1))
        .map_err(|_| ExchangeError::FetchBitcoinCanisterError)?;
    let mut utxos = vec![];
    for utxo in response.utxos {
        utxos.push(Utxo {
            txid: Txid::from_bytes(utxo.outpoint.txid.as_slice())
                .map_err(|_| ExchangeError::InvalidTxid)?,
            vout: utxo.outpoint.vout,
            maybe_rune: None,
            sats: utxo.value,
        });
    }

    let (runes,): (rune_indexer::Result_,) = indexer
        .get_rune_balances_for_outputs(utxos.iter().map(|utxo| utxo.outpoint()).collect::<Vec<_>>())
        .await
        .map_err(|_| ExchangeError::FetchRuneIndexerError)?;

    match runes {
        rune_indexer::Result_::Ok(runes) => {
            (runes.len() == utxos.len())
                .then(|| ())
                .ok_or(ExchangeError::RuneIndexerError(
                    "UTXOs mismatch".to_string(),
                ))?;
            for (i, utxo) in utxos.iter_mut().enumerate() {
                utxo.maybe_rune = runes[i]
                    .as_ref()
                    .map(|rs| {
                        rs.iter()
                            .find(|r| r.rune_id == pool.meta.id.to_string())
                            .map(|b| CoinBalance {
                                id: CoinId::from_str(&b.rune_id).unwrap(),
                                value: b.amount,
                            })
                            .clone()
                    })
                    .flatten();
            }
        }
        rune_indexer::Result_::Err(_) => {
            return Err(ExchangeError::RuneIndexerError("".to_string()));
        }
    }
    Ok(utxos
        .into_iter()
        .map(|utxo| (utxo.outpoint(), utxo.clone()))
        .collect())
}

pub fn get_edicts_in_tx(tx: &ree_types::bitcoin::Transaction) -> Result<Vec<Edict>, ExchangeError> {
    let maybe_runestone = Runestone::decipher(tx);
    if let Some(artifact) = maybe_runestone {
        match artifact {
            Artifact::Runestone(rune_stone) => {
                if rune_stone.etching.is_some() {
                    return Err(ExchangeError::InvalidPsbt("".to_string()));
                }
                if rune_stone.mint.is_some() {
                    return Err(ExchangeError::InvalidPsbt("".to_string()));
                }
                if rune_stone.pointer.is_some() {
                    return Err(ExchangeError::InvalidPsbt("".to_string()));
                }
                return Ok(rune_stone.edicts.clone());
            }
            Artifact::Cenotaph(_) => {
                return Err(ExchangeError::InvalidPsbt("".to_string()));
            }
        }
    }
    Ok(Vec::new())
}
