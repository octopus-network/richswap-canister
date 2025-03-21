use crate::pool::{CoinMeta, LiquidityPool, PoolState, Share};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use ree_types::{Pubkey, Txid, Utxo};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPoolV2 {
    pub states: Vec<PoolStateV2>,
    pub fee_rate: u64,
    pub burn_rate: u64,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
    pub tweaked: Pubkey,
    pub addr: String,
}

impl Into<LiquidityPool> for LiquidityPoolV2 {
    fn into(self) -> LiquidityPool {
        LiquidityPool {
            states: self
                .states
                .into_iter()
                .map(|s| s.into())
                .collect::<Vec<_>>(),
            fee_rate: self.fee_rate,
            burn_rate: self.burn_rate,
            meta: self.meta,
            pubkey: self.pubkey,
            tweaked: self.tweaked,
            addr: self.addr,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
pub struct PoolStateV2 {
    pub id: Option<Txid>,
    pub nonce: u64,
    pub utxo: Option<Utxo>,
    pub incomes: u64,
    pub k: u128,
    pub lp: BTreeMap<String, u128>,
}

impl Into<PoolState> for PoolStateV2 {
    fn into(self) -> PoolState {
        let mut lp = BTreeMap::new();
        for (k, v) in self.lp {
            lp.insert(
                k,
                Share {
                    incomes: 0,
                    share: v,
                },
            );
        }
        PoolState {
            id: self.id,
            nonce: self.nonce,
            utxo: self.utxo,
            incomes: self.incomes,
            k: self.k,
            lp,
        }
    }
}

impl Storable for PoolStateV2 {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut bytes = vec![];
        let _ = ciborium::ser::into_writer(self, &mut bytes);
        std::borrow::Cow::Owned(bytes)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        let dire = ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode Pool");
        dire
    }
}

impl Storable for LiquidityPoolV2 {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut bytes = vec![];
        let _ = ciborium::ser::into_writer(self, &mut bytes);
        std::borrow::Cow::Owned(bytes)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        let dire = ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode Pool");
        dire
    }
}

#[allow(unused)]
pub(crate) fn migrate_to_v3() {
    let is_empty = crate::POOLS.with_borrow(|p| p.is_empty());
    if !is_empty {
        return;
    }
    crate::POOLS_V2.with(|p| {
        let pools = p.borrow().iter().map(|p| p.1.clone()).collect::<Vec<_>>();
        for pool in pools {
            let pool: crate::pool::LiquidityPool = pool.into();
            let id = pool.meta.id;
            let addr = pool.addr.clone();
            let untweaked = pool.pubkey.clone();
            crate::POOL_TOKENS.with_borrow_mut(|l| {
                l.insert(id, untweaked.clone());
                crate::POOLS.with_borrow_mut(|p| {
                    p.insert(untweaked.clone(), pool);
                });
                crate::POOL_ADDR.with_borrow_mut(|p| p.insert(addr, untweaked));
            });
        }
    });
}
