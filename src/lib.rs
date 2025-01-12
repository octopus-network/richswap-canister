#![feature(isqrt)]
mod canister;
mod ic_log;
mod pool;
mod psbt;

use crate::pool::{CoinMeta, LiquidityPool, DEFAULT_BURN_RATE, DEFAULT_FEE_RATE};
use candid::{
    types::{Serializer, Type, TypeInner},
    CandidType, Deserialize,
};
use ic_cdk::api::management_canister::{
    ecdsa::{
        self, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument, SignWithEcdsaArgument,
        SignWithEcdsaResponse,
    },
    schnorr::{
        self, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument, SignWithSchnorrArgument,
        SignWithSchnorrResponse,
    },
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    Cell, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use serde::Serialize;
use std::{cell::RefCell, str::FromStr};
use thiserror::Error;

pub const MIN_RESERVED_SATOSHIS: u64 = 546;
pub const RUNE_INDEXER_CANISTER: &'static str = "o25oi-jaaaa-aaaal-ajj6a-cai";

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

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Debug)]
pub struct Pubkey(pub(crate) bitcoin::PublicKey);

impl Pubkey {
    pub fn from_raw(key: Vec<u8>) -> Result<Pubkey, String> {
        bitcoin::PublicKey::from_slice(&key)
            .map(|s| Pubkey(s))
            .map_err(|_| "invalid pubkey".to_string())
    }

    pub fn p2wpkh_addr(&self) -> String {
        bitcoin::Address::p2wpkh(
            &bitcoin::key::CompressedPublicKey(self.0.inner),
            bitcoin::Network::Bitcoin,
        )
        .to_string()
    }

    pub fn pubkey_hash(&self) -> bitcoin::PubkeyHash {
        self.0.pubkey_hash()
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
        max_size: 33,
        is_fixed_size: true,
    };

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.0.to_bytes())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(bitcoin::PublicKey::from_slice(&bytes).expect("invalid pubkey"))
    }
}

impl std::str::FromStr for Pubkey {
    type Err = ExchangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bitcoin::PublicKey::from_str(s)
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
}

impl<'de> serde::Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Pubkey, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(PubkeyVisitor)
    }
}

impl serde::Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
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

impl From<bitcoin::Txid> for Txid {
    fn from(txid: bitcoin::Txid) -> Self {
        Self(*AsRef::<[u8; 32]>::as_ref(&txid))
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

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
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
    #[error("couldn't derive a chain key for pool")]
    ChainKeyError,
    #[error("invalid psbt: {0}")]
    InvalidPsbt(String),
    #[error("invalid pool state: {0}")]
    InvalidState(String),
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

const POOLS_MEMORY_ID: MemoryId = MemoryId::new(0);
const POOL_TOKENS_MEMORY_ID: MemoryId = MemoryId::new(1);
const FEE_COLLECTOR_MEMORY_ID: MemoryId = MemoryId::new(2);

thread_local! {
    static MEMORY: RefCell<Option<DefaultMemoryImpl>> = RefCell::new(Some(DefaultMemoryImpl::default()));

    static MEMORY_MANAGER: RefCell<Option<MemoryManager<DefaultMemoryImpl>>> =
        RefCell::new(Some(MemoryManager::init(MEMORY.with(|m| m.borrow().clone().unwrap()))));

    static POOLS: RefCell<StableBTreeMap<Pubkey, LiquidityPool, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOLS_MEMORY_ID))));

    static POOL_TOKENS: RefCell<StableBTreeMap<CoinId, Pubkey, Memory>> =
        RefCell::new(StableBTreeMap::init(with_memory_manager(|m| m.get(POOL_TOKENS_MEMORY_ID))));

    // TODO
    static FEE_COLLECTOR: RefCell<Cell<Pubkey, Memory>> =
        RefCell::new(Cell::init(with_memory_manager(|m| m.get(FEE_COLLECTOR_MEMORY_ID)),
                                Pubkey::from_str("").unwrap()).expect("fail to init a StableCell"));
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

pub(crate) fn reset_all_pools() {
    POOLS.with_borrow_mut(|p| p.clear_new());
    POOL_TOKENS.with_borrow_mut(|p| p.clear_new());
}

pub(crate) fn has_pool(id: &CoinId) -> bool {
    POOL_TOKENS.with_borrow(|p| p.contains_key(&id))
}

pub(crate) fn with_pool_name(id: &CoinId) -> Option<Pubkey> {
    POOL_TOKENS.with_borrow(|p| p.get(&id))
}

pub(crate) async fn request_schnorr_key(
    key_name: String,
    path: Vec<u8>,
) -> Result<Pubkey, ExchangeError> {
    let arg = SchnorrPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![path],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_name,
        },
    };
    let res = schnorr::schnorr_public_key(arg)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    let pubkey =
        Pubkey::from_raw(res.0.public_key.to_vec()).expect("management api error: invalid pubkey");
    Ok(pubkey)
}

pub(crate) async fn request_ecdsa_key(
    key_name: String,
    path: Vec<u8>,
) -> Result<Pubkey, ExchangeError> {
    let args = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![path],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    let res = ecdsa::ecdsa_public_key(args)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    let pubkey =
        Pubkey::from_raw(res.0.public_key.to_vec()).expect("management api error: invalid pubkey");
    Ok(pubkey)
}

pub(crate) async fn sign_prehash_with_schnorr(
    digest: impl AsRef<[u8; 32]>,
    key_name: String,
    path: Vec<u8>,
) -> Result<Vec<u8>, ExchangeError> {
    let args = SignWithSchnorrArgument {
        message: digest.as_ref().to_vec(),
        derivation_path: vec![path],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_name,
        },
    };
    let (sig,): (SignWithSchnorrResponse,) = schnorr::sign_with_schnorr(args)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    Ok(sig.signature)
}

pub(crate) async fn sign_prehash_with_ecdsa(
    digest: impl AsRef<[u8; 32]>,
    key_name: String,
    path: Vec<u8>,
) -> Result<Vec<u8>, ExchangeError> {
    let args = SignWithEcdsaArgument {
        message_hash: digest.as_ref().to_vec(),
        derivation_path: vec![path],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    let (sig,): (SignWithEcdsaResponse,) = ecdsa::sign_with_ecdsa(args)
        .await
        .map_err(|(_, _)| ExchangeError::ChainKeyError)?;
    Ok(sig.signature)
}

pub(crate) fn create_empty_pool(meta: CoinMeta, pubkey: Pubkey) -> Result<(), ExchangeError> {
    if has_pool(&meta.id) {
        return Err(ExchangeError::PoolAlreadyExists);
    }
    let id = meta.id;
    let pool = LiquidityPool::new_empty(meta, DEFAULT_FEE_RATE, DEFAULT_BURN_RATE, pubkey.clone())
        .expect("didn't set fee rate");
    POOL_TOKENS.with_borrow_mut(|l| {
        l.insert(id, pubkey.clone());
        POOLS.with_borrow_mut(|p| {
            p.insert(pubkey, pool);
        });
    });
    Ok(())
}

pub(crate) fn get_fee_collector() -> Pubkey {
    FEE_COLLECTOR.with(|f| f.borrow().get().clone())
}

pub(crate) fn set_fee_collector(pubkey: Pubkey) {
    let _ = FEE_COLLECTOR.with(|f| f.borrow_mut().set(pubkey));
}

/// sqrt(x) * sqrt(x) <= x
pub(crate) fn sqrt(x: u128) -> u128 {
    x.isqrt()
}

#[test]
pub fn ser_deser_pubkey() {
    use std::str::FromStr;
    let pk = Pubkey::from_str("03b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76");
    assert!(pk.is_ok());
}

#[test]
pub fn test_derive_p2tr_addr() {
    use bitcoin::key::Secp256k1;
    use bitcoin::Address;
    use bitcoin::Network;
    use bitcoin::XOnlyPublicKey;

    let x_only_pubkey_hex = "b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76";
    let x_only_pubkey_bytes = hex::decode(x_only_pubkey_hex).expect("Invalid hex");

    let x_only_pubkey =
        XOnlyPublicKey::from_slice(&x_only_pubkey_bytes).expect("Invalid x-only pubkey");

    let address = Address::p2tr(&Secp256k1::new(), x_only_pubkey, None, Network::Bitcoin);

    println!("Taproot Address: {}", address);
}

#[test]
pub fn test_derive_p2wpkh_addr() {
    use bitcoin::Address;
    use bitcoin::CompressedPublicKey;
    use bitcoin::Network;

    let pubkey_hex = "021774b3f1c2d9f8e51529eda4a54624e2f067826b42281fb5b9a9b40fd4a967e9";
    let pubkey_bytes = hex::decode(pubkey_hex).expect("Invalid hex");

    let pubkey = CompressedPublicKey::from_slice(&pubkey_bytes).expect("Invalid pubkey");
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin);

    println!("Segwit Address: {}", address);
    assert!(false);
}
