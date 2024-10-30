mod canister;
mod decimal;
mod pool;

use crate::pool::LiquidityPool;
use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::cell::{Cell, RefCell};
use thiserror::Error;

pub use bitcoin::{
    address::{Address, NetworkUnchecked},
    block::Header,
    blockdata::{
        constants::{DIFFCHANGE_INTERVAL, MAX_SCRIPT_ELEMENT_SIZE, SUBSIDY_HALVING_INTERVAL},
        locktime::absolute::LockTime,
    },
    consensus::{self, encode, Decodable, Encodable},
    hash_types::{BlockHash, TxMerkleNode},
    hashes::Hash,
    script, Amount, Block, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
pub use decimal::Decimal;

pub const MIN_RESERVED_SATOSHIS: u64 = 546;

#[derive(Eq, PartialEq, Clone, CandidType, Debug, Deserialize, Serialize)]
pub struct Output {
    pub balance: CoinBalance,
    pub address: String,
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub tx_id: [u8; 32],
    pub vout: u32,
    pub balance: CoinBalance,
    pub satoshis: u64,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, CandidType, Deserialize, Serialize)]
pub struct CoinId {
    pub block: u64,
    pub tx: u32,
}

impl CoinId {
    pub fn rune(block: u64, tx: u32) -> Self {
        Self { block, tx }
    }

    #[inline]
    pub const fn btc() -> Self {
        Self { block: 0, tx: 0 }
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
}

thread_local! {
    static POOL: RefCell<Option<LiquidityPool>> = RefCell::new(None);
}

pub(crate) fn new_pool(pool: LiquidityPool) {
    POOL.with(|p| p.replace(Some(pool)));
}

pub(crate) fn with_pool<F, R>(f: F) -> R
where
    F: Fn(&LiquidityPool) -> R,
{
    POOL.with_borrow(|p| f(p.as_ref().expect("pool not initialized")))
}
