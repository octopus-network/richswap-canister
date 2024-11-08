mod canister;
mod decimal;
mod pool;

use crate::pool::{CoinMeta, LiquidityPool, DEFAULT_FEE_RATE};
use candid::{
    types::{Serializer, Type, TypeInner},
    CandidType, Deserialize,
};
pub use decimal::Decimal;
use ic_cdk::api::management_canister::schnorr::{
    self, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument, SchnorrPublicKeyResponse,
    SignWithSchnorrArgument, SignWithSchnorrResponse,
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use serde::Serialize;
use std::cell::RefCell;
use thiserror::Error;

pub const MIN_RESERVED_SATOSHIS: u64 = 546;

#[derive(Eq, PartialEq, Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct Output {
    pub balance: CoinBalance,
    pub pubkey: Pubkey,
}

#[derive(Eq, CandidType, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub balance: CoinBalance,
    pub satoshis: u64,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Debug, Serialize)]
pub struct Pubkey(bitcoin::XOnlyPublicKey);

impl Pubkey {
    pub fn from_raw(key: Vec<u8>) -> Self {
        Self(bitcoin::XOnlyPublicKey::from_slice(&key).expect("invalid pubkey"))
    }
}

impl CandidType for Pubkey {
    fn _ty() -> Type {
        TypeInner::Text.into()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_text(&self.0.to_string())
    }
}

impl Storable for Pubkey {
    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.0.serialize().to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(bitcoin::XOnlyPublicKey::from_slice(&bytes).expect("invalid pubkey"))
    }
}

impl std::str::FromStr for Pubkey {
    type Err = ExchangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bitcoin::XOnlyPublicKey::from_str(s)
            .map(|pk| Self(pk))
            .map_err(|_| ExchangeError::InvalidNumeric)
    }
}

struct PubkeyVisitor;

impl<'de> serde::de::Visitor<'de> for PubkeyVisitor {
    type Value = Pubkey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a Bitcoin Pubkey")
    }

    fn visit_str<E>(self, value: &str) -> Result<Pubkey, E>
    where
        E: serde::de::Error,
    {
        use std::str::FromStr;
        Pubkey::from_str(value)
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(value), &self))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Pubkey, E>
    where
        E: serde::de::Error,
    {
        Ok(Pubkey(bitcoin::XOnlyPublicKey::from_slice(v).map_err(
            |_| E::invalid_value(serde::de::Unexpected::Bytes(v), &"a Bitcoin Pubkey"),
        )?))
    }
}

impl<'de> serde::Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Pubkey, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(PubkeyVisitor)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Txid([u8; 32]);

impl CandidType for Txid {
    fn _ty() -> Type {
        TypeInner::Text.into()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        let rev = self.0.iter().rev().copied().collect::<Vec<_>>();
        serializer.serialize_text(&hex::encode(&rev))
    }
}

impl std::str::FromStr for Txid {
    type Err = ExchangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bitcoin::Txid::from_str(s).map_err(|_| ExchangeError::InvalidTxid)?;
        Ok(Self(*AsRef::<[u8; 32]>::as_ref(&bytes)))
    }
}

impl Into<bitcoin::Txid> for Txid {
    fn into(self) -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        bitcoin::Txid::from_byte_array(self.0)
    }
}

impl std::fmt::Display for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let rev = self.0.iter().rev().copied().collect::<Vec<_>>();
        write!(f, "{}", hex::encode(&rev))
    }
}

struct TxidVisitor;

impl<'de> serde::de::Visitor<'de> for TxidVisitor {
    type Value = Txid;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a Bitcoin Txid")
    }

    fn visit_str<E>(self, value: &str) -> Result<Txid, E>
    where
        E: serde::de::Error,
    {
        use std::str::FromStr;
        Txid::from_str(value)
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(value), &self))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Txid, E>
    where
        E: serde::de::Error,
    {
        Ok(Txid(v.try_into().map_err(|_| {
            E::invalid_value(serde::de::Unexpected::Bytes(v), &"a Bitcoin Txid")
        })?))
    }
}

impl<'de> serde::Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Txid, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(TxidVisitor)
    }
}

impl serde::Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CoinId {
    pub block: u64,
    pub tx: u32,
}

impl Ord for CoinId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block.cmp(&other.block).then(self.tx.cmp(&other.tx))
    }
}

impl PartialOrd for CoinId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Storable for CoinId {
    const BOUND: Bound = Bound::Bounded {
        max_size: 12,
        is_fixed_size: true,
    };

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut bytes = vec![];
        bytes.extend_from_slice(self.block.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.tx.to_be_bytes().as_ref());
        std::borrow::Cow::Owned(bytes)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        let block: [u8; 8] = bytes.as_ref()[0..8]
            .try_into()
            .expect("failed to decode CoinId");
        let tx: [u8; 4] = bytes.as_ref()[8..12]
            .try_into()
            .expect("failed to decode CoinId");
        Self {
            block: u64::from_be_bytes(block),
            tx: u32::from_be_bytes(tx),
        }
    }
}

impl CoinId {
    pub fn rune(block: u64, tx: u32) -> Self {
        Self { block, tx }
    }

    #[inline]
    pub const fn btc() -> Self {
        Self { block: 0, tx: 0 }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(self.block.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.tx.to_be_bytes().as_ref());
        bytes
    }
}

impl std::str::FromStr for CoinId {
    type Err = ExchangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let block = parts
            .next()
            .map(|s| s.parse().ok())
            .flatten()
            .ok_or(ExchangeError::InvalidNumeric)?;
        let tx = parts
            .next()
            .map(|s| s.parse().ok())
            .flatten()
            .ok_or(ExchangeError::InvalidNumeric)?;
        Ok(Self { block, tx })
    }
}

impl serde::Serialize for CoinId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl CandidType for CoinId {
    fn _ty() -> Type {
        TypeInner::Text.into()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_text(&self.to_string())
    }
}

impl std::fmt::Display for CoinId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.block, self.tx)
    }
}

struct CoinIdVisitor;

impl<'de> serde::de::Visitor<'de> for CoinIdVisitor {
    type Value = CoinId;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Id of a coin in btc")
    }

    fn visit_str<E>(self, value: &str) -> Result<CoinId, E>
    where
        E: serde::de::Error,
    {
        use std::str::FromStr;
        CoinId::from_str(value)
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(value), &self))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<CoinId, E>
    where
        E: serde::de::Error,
    {
        let block: [u8; 8] = v[0..8].try_into().expect("failed to decode CoinId");
        let tx: [u8; 4] = v[8..12].try_into().expect("failed to decode CoinId");
        Ok(CoinId {
            block: u64::from_be_bytes(block),
            tx: u32::from_be_bytes(tx),
        })
    }
}

impl<'de> serde::Deserialize<'de> for CoinId {
    fn deserialize<D>(deserializer: D) -> Result<CoinId, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(CoinIdVisitor)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, CandidType, Deserialize, Serialize)]
pub struct CoinBalance {
    pub id: CoinId,
    pub value: u128,
}

impl CoinBalance {
    pub fn decimal(&self, divisibility: u8) -> Option<Decimal> {
        let v: i128 = self.value.try_into().ok()?;
        if v < 0 {
            None
        } else {
            Decimal::try_from_primitive(v, divisibility as u32)
        }
    }

    pub fn from_decimal(value: Decimal, divisibility: u8, id: CoinId) -> Self {
        let mut v = value.truncate(divisibility);
        v.set_scale(0);
        Self {
            id,
            value: v.mantissa() as u128,
        }
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
    #[error("invalid requirements")]
    InvalidRequirements,
    #[error("too small funds")]
    TooSmallFunds,
    #[error("invalid amount: the given inputs couldn't cover the btc fee")]
    FeeNotEnough,
    #[error("invalid amount: the given inputs less than required amount")]
    AmountGreaterThanUtxo,
    #[error("invalid txid")]
    InvalidTxid,
    #[error("invalid numeric")]
    InvalidNumeric,
    #[error("a pool with the given id already exists")]
    PoolAlreadyExists,
    #[error("a pool requires btc")]
    BtcRequired,
    #[error("the pool has not been initialized or has been removed")]
    EmptyPool,
    #[error("couldn't derive a chain key for pool")]
    ChainKeyError,
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

const POOLS_MEMORY_ID: MemoryId = MemoryId::new(0);
const POOL_TOKENS_MEMORY_ID: MemoryId = MemoryId::new(1);

thread_local! {
    static MEMORY: RefCell<Option<DefaultMemoryImpl>> = RefCell::new(Some(DefaultMemoryImpl::default()));

    static MEMORY_MANAGER: RefCell<Option<MemoryManager<DefaultMemoryImpl>>> =
        RefCell::new(Some(MemoryManager::init(MEMORY.with(|m| m.borrow().clone().unwrap()))));

    static POOLS: RefCell<StableBTreeMap<Pubkey, LiquidityPool, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOLS_MEMORY_ID))));

    static POOL_TOKENS: RefCell<StableBTreeMap<CoinId, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOL_TOKENS_MEMORY_ID))));
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

pub(crate) fn has_pool(id: &CoinId) -> bool {
    POOL_TOKENS.with_borrow(|p| p.contains_key(&id))
}

pub(crate) async fn create_pool(x: CoinMeta, y: CoinMeta) -> Result<Pubkey, ExchangeError> {
    let base_id = if x.id == CoinId::btc() { y.id } else { x.id };
    if has_pool(&base_id) {
        return Err(ExchangeError::PoolAlreadyExists);
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "dev")] {
            let arg = SchnorrPublicKeyArgument {
                canister_id: None,
                derivation_path: vec![base_id.to_bytes()],
                key_id: SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: "dfx_test_key".to_string(),
                },
            };
            let res = schnorr::schnorr_public_key(arg)
                .await
                .inspect_err(|(_, e)| ic_cdk::println!("{:?}", e))
                .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
            let pubkey = Pubkey::from_raw(res.0.public_key);
        } else {
            let arg = SchnorrPublicKeyArgument {
                canister_id: None,
                derivation_path: vec![base_id.to_bytes()],
                key_id: SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: base_id.to_string(),
                },
            };
            let res = schnorr::schnorr_public_key(arg)
                .await
                .inspect_err(|(_, e)| ic_cdk::println!("{:?}", e))
                .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
            let pubkey = Pubkey::from_raw(res.0.public_key);
        }
    }

    let pool = LiquidityPool::new(x, y, *DEFAULT_FEE_RATE, pubkey.clone());
    POOL_TOKENS.with_borrow_mut(|l| {
        l.insert(base_id, pubkey.clone());
        POOLS.with_borrow_mut(|p| {
            p.insert(pubkey.clone(), pool);
        });
    });
    Ok(pubkey)
}
