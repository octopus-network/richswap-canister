mod canister;
mod pool;
mod psbt;

use crate::pool::{CoinMeta, LiquidityPool, DEFAULT_BURN_RATE, DEFAULT_FEE_RATE};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::schnorr::{
    self, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument,
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    Cell, DefaultMemoryImpl, StableBTreeMap,
};
use ree_types::{
    bitcoin::{key::TapTweak, secp256k1::Secp256k1, Address, Network},
    exchange_interfaces::CoinBalance,
    CoinId, Pubkey, Txid,
};
use serde::Serialize;
use std::cell::RefCell;
use std::str::FromStr;
use thiserror::Error;

pub const MIN_RESERVED_SATOSHIS: u64 = 546;
pub const RUNE_INDEXER_CANISTER: &'static str = "kzrva-ziaaa-aaaar-qamyq-cai";
pub const ORCHESTRATOR_CANISTER: &'static str = "kqs64-paaaa-aaaar-qamza-cai";
pub const DEFAULT_FEE_COLLECTOR: &'static str =
    "269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9";

#[derive(Eq, PartialEq, Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct Output {
    pub balance: CoinBalance,
    pub pubkey: Pubkey,
}

#[derive(CandidType, Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub balance: CoinBalance,
    pub satoshis: u64,
}

impl Utxo {
    pub fn try_from(
        outpoint: impl AsRef<str>,
        rune: CoinBalance,
        sats: u64,
    ) -> Result<Self, ExchangeError> {
        let parts = outpoint.as_ref().split(':').collect::<Vec<_>>();
        let txid = parts
            .get(0)
            .map(|s| Txid::from_str(s).map_err(|_| ExchangeError::InvalidTxid))
            .transpose()?
            .ok_or(ExchangeError::InvalidTxid)?;
        let vout = parts
            .get(1)
            .map(|s| s.parse::<u32>().map_err(|_| ExchangeError::InvalidNumeric))
            .transpose()?
            .ok_or(ExchangeError::InvalidNumeric)?;
        Ok(Utxo {
            txid,
            vout,
            balance: rune,
            satoshis: sats,
        })
    }

    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
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
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

const POOLS_MEMORY_ID: MemoryId = MemoryId::new(0);
const POOL_TOKENS_MEMORY_ID: MemoryId = MemoryId::new(1);
const FEE_COLLECTOR_MEMORY_ID: MemoryId = MemoryId::new(2);
const ORCHESTRATOR_MEMORY_ID: MemoryId = MemoryId::new(3);
const POOL_ADDR_MEMORY_ID: MemoryId = MemoryId::new(4);

thread_local! {
    static MEMORY: RefCell<Option<DefaultMemoryImpl>> = RefCell::new(Some(DefaultMemoryImpl::default()));

    static MEMORY_MANAGER: RefCell<Option<MemoryManager<DefaultMemoryImpl>>> =
        RefCell::new(Some(MemoryManager::init(MEMORY.with(|m| m.borrow().clone().unwrap()))));

    static POOLS: RefCell<StableBTreeMap<Pubkey, LiquidityPool, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOLS_MEMORY_ID))));

    static POOL_TOKENS: RefCell<StableBTreeMap<CoinId, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOL_TOKENS_MEMORY_ID))));

    static POOL_ADDR: RefCell<StableBTreeMap<String, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOL_ADDR_MEMORY_ID))));

    static FEE_COLLECTOR: RefCell<Cell<Pubkey, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(FEE_COLLECTOR_MEMORY_ID)), Pubkey::from_str(DEFAULT_FEE_COLLECTOR).expect("invalid pubkey: fee collector"))
                     .expect("fail to init a StableCell"));

    static ORCHESTRATOR: RefCell<Cell<Principal, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(ORCHESTRATOR_MEMORY_ID)), Principal::from_str(ORCHESTRATOR_CANISTER).expect("invalid principal: orchestrator"))
                     .expect("fail to init a StableCell"));
}

fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<DefaultMemoryImpl>) -> R) -> R {
    MEMORY_MANAGER.with(|cell| {
        f(cell
            .borrow()
            .as_ref()
            .expect("memory manager not initialized"))
    })
}

pub(crate) fn with_pool<F, R>(id: &Pubkey, f: F) -> R
where
    F: Fn(&Option<LiquidityPool>) -> R,
{
    POOLS.with_borrow(|p| {
        let pool = p.get(&id);
        f(&pool)
    })
}

pub(crate) fn with_pool_mut<F>(id: &Pubkey, f: F) -> Result<(), ExchangeError>
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

pub(crate) fn find_pool(pubkey: &Pubkey) -> Option<LiquidityPool> {
    with_pool(pubkey, |p| p.clone())
}

pub(crate) fn has_pool(id: &CoinId) -> bool {
    POOL_TOKENS.with_borrow(|p| p.contains_key(&id))
}

pub(crate) fn with_pool_name(id: &CoinId) -> Option<Pubkey> {
    POOL_TOKENS.with_borrow(|p| p.get(&id))
}

pub(crate) fn with_pool_addr(addr: &String) -> Option<Pubkey> {
    POOL_ADDR.with_borrow(|p| p.get(addr))
}

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

pub(crate) async fn sign_prehash_with_ecdsa(
    digest: impl AsRef<[u8; 32]>,
    key_name: impl ToString,
    path: Vec<u8>,
) -> Result<Vec<u8>, ExchangeError> {
    use ic_cdk::api::management_canister::ecdsa::{
        self, EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument, SignWithEcdsaResponse,
    };
    let args = SignWithEcdsaArgument {
        message_hash: digest.as_ref().to_vec(),
        derivation_path: vec![path],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name.to_string(),
        },
    };
    let (sig,): (SignWithEcdsaResponse,) = ecdsa::sign_with_ecdsa(args)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    Ok(sig.signature)
}

pub(crate) fn create_empty_pool(meta: CoinMeta, untweaked: Pubkey) -> Result<(), ExchangeError> {
    if has_pool(&meta.id) {
        return Err(ExchangeError::PoolAlreadyExists);
    }
    let id = meta.id;
    let pool =
        LiquidityPool::new_empty(meta, DEFAULT_FEE_RATE, DEFAULT_BURN_RATE, untweaked.clone())
            .expect("didn't set fee rate");
    POOL_TOKENS.with_borrow_mut(|l| {
        l.insert(id, untweaked.clone());
        POOLS.with_borrow_mut(|p| {
            p.insert(untweaked, pool);
        });
    });
    Ok(())
}

pub(crate) fn p2tr_untweaked(pubkey: &Pubkey) -> String {
    let untweaked = pubkey.to_x_only_public_key();
    let address = Address::p2tr(&Secp256k1::new(), untweaked, None, Network::Bitcoin);
    address.to_string()
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

pub(crate) fn set_orchestrator(principal: Principal) {
    let _ = ORCHESTRATOR.with(|o| o.borrow_mut().set(principal));
}

/// sqrt(x) * sqrt(x) <= x
pub(crate) fn sqrt(x: u128) -> u128 {
    x.isqrt()
}
