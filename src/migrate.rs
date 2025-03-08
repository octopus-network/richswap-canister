use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use ree_types_old::{exchange_interfaces::CoinBalance, CoinId, Pubkey, Txid};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Eq, CandidType, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct UtxoV1 {
    pub txid: Txid,
    pub vout: u32,
    pub balance: CoinBalance,
    pub satoshis: u64,
}

impl Into<crate::Utxo> for UtxoV1 {
    fn into(self) -> crate::Utxo {
        crate::Utxo {
            txid: ree_types::Txid::from_bytes(self.txid.as_ref())
                .expect("migrating failed: Txid in Utxo uncompatible"),
            vout: self.vout,
            sats: self.satoshis,
            maybe_rune: Some(ree_types::CoinBalance {
                id: ree_types::CoinId::rune(self.balance.id.block, self.balance.id.tx),
                value: self.balance.value,
            }),
        }
    }
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoinMetaV1 {
    pub id: CoinId,
    pub symbol: String,
    pub min_amount: u128,
}

impl Into<crate::CoinMeta> for CoinMetaV1 {
    fn into(self) -> crate::CoinMeta {
        crate::CoinMeta {
            id: ree_types::CoinId::rune(self.id.block, self.id.tx),
            symbol: self.symbol,
            min_amount: self.min_amount,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
pub struct PoolStateV1 {
    pub id: Option<Txid>,
    pub nonce: u64,
    pub utxo: Option<UtxoV1>,
    pub incomes: u64,
    pub k: u128,
    pub lp: BTreeMap<String, u128>,
}

impl Into<crate::pool::PoolState> for PoolStateV1 {
    fn into(self) -> crate::pool::PoolState {
        let utxo = self.utxo.map(|utxo| utxo.into());
        let lp = self.lp.into_iter().collect();
        crate::pool::PoolState {
            id: self.id.map(|id| {
                ree_types::Txid::from_bytes(id.as_ref())
                    .expect("migrating failed: Txid in PoolState uncompatible")
            }),
            nonce: self.nonce,
            utxo,
            incomes: self.incomes,
            k: self.k,
            lp,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPoolV1 {
    pub states: Vec<PoolStateV1>,
    pub fee_rate: u64,
    pub burn_rate: u64,
    pub meta: CoinMetaV1,
    pub pubkey: Pubkey,
    pub tweaked: Pubkey,
    pub addr: String,
}

impl Into<crate::pool::LiquidityPool> for LiquidityPoolV1 {
    fn into(self) -> crate::pool::LiquidityPool {
        let states = self.states.into_iter().map(|state| state.into()).collect();
        crate::pool::LiquidityPool {
            states,
            fee_rate: self.fee_rate,
            burn_rate: self.burn_rate,
            meta: self.meta.into(),
            pubkey: ree_types::Pubkey::from_raw(self.pubkey.as_bytes().to_vec())
                .expect("migrating failed: pubkey in pool uncompatible"),
            tweaked: ree_types::Pubkey::from_raw(self.tweaked.as_bytes().to_vec())
                .expect("migrating failed: pubkey in pool uncompatible"),
            addr: self.addr,
        }
    }
}

impl Storable for PoolStateV1 {
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

impl Storable for LiquidityPoolV1 {
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
