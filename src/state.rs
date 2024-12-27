use candid::{
    types::{Serializer, Type, TypeInner},
    CandidType, Deserialize,
};
use serde::Serialize;

pub trait State<T: Clone + Deserialize + Serialize> {}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolState {
    pub txid: Txid,
    pub nonce: u64,
    pub btc_utxo: Utxo,
    pub rune_utxo: Utxo,
    pub incomes: u128,
    pub fee_rate: u128,
    pub k: u128,
}

impl Storable for PoolState {
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

pub(crate) fn rollback<K>(k: K) {}

pub(crate) fn finalize<K>(k: K) {}

pub(crate) fn commit<K>(k: K) {}
