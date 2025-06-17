use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use ree_types::{Pubkey, Txid};
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPoolV4 {
    pub states: Vec<PoolStateV4>,
    pub fee_rate: u64,
    pub burn_rate: u64,
    pub meta: crate::CoinMeta,
    pub pubkey: Pubkey,
    pub tweaked: Pubkey,
    pub addr: String,
}

impl Into<crate::pool::LiquidityPool> for LiquidityPoolV4 {
    fn into(self) -> crate::pool::LiquidityPool {
        crate::pool::LiquidityPool {
            states: self.states.into_iter().map(|s| s.into()).collect(),
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
pub struct PoolStateV4 {
    pub id: Option<Txid>,
    pub nonce: u64,
    pub utxo: Option<ree_types_v4::Utxo>,
    pub incomes: u64,
    pub k: u128,
    pub lp: BTreeMap<String, u128>,
    #[serde(default)]
    pub lp_earnings: BTreeMap<String, u64>,
}

impl Into<crate::pool::PoolState> for PoolStateV4 {
    fn into(self) -> crate::pool::PoolState {
        crate::pool::PoolState {
            id: self.id,
            nonce: self.nonce,
            utxo: self.utxo.map(|utxo| into_v5_utxo(utxo)),
            incomes: self.incomes,
            k: self.k,
            lp: self.lp,
            lp_earnings: self.lp_earnings,
            total_btc_donation: 0,
            total_rune_donation: 0,
        }
    }
}

fn into_v5_utxo(utxo: ree_types_v4::Utxo) -> ree_types::Utxo {
    let mut coins = ree_types::CoinBalances::new();
    if let Some(r) = utxo.maybe_rune.as_ref() {
        let rune = ree_types::CoinBalance {
            id: ree_types::CoinId::rune(r.id.block, r.id.tx),
            value: r.value,
        };
        coins.add_coin(&rune);
    }
    ree_types::Utxo {
        txid: ree_types::Txid::from_str(utxo.txid.to_string().as_str())
            .expect("failed to convert txid"),
        vout: utxo.vout,
        sats: utxo.sats,
        coins,
    }
}

impl Storable for PoolStateV4 {
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

impl Storable for LiquidityPoolV4 {
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
pub(crate) fn migrate_to_v5() {
    let is_empty = crate::POOLS.with_borrow(|p| p.is_empty());
    if !is_empty {
        return;
    }
    crate::POOLS_V4.with(|p| {
        let pools = p.borrow().iter().map(|p| p.1.clone()).collect::<Vec<_>>();
        for pool in pools.into_iter() {
            let addr = pool.addr.clone();
            crate::POOLS.with_borrow_mut(|p| {
                p.insert(addr, pool.into());
            });
        }
    });
}
