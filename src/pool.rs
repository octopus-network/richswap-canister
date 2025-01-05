use crate::{CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use serde::Serialize;
use std::collections::BTreeMap;

/// represents 0.9/100 = 9/1_000 = 900/1_000_000
pub const DEFAULT_FEE_RATE: u128 = 900;

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoinMeta {
    pub id: CoinId,
    pub symbol: String,
    pub min_amount: u128,
}

impl CoinMeta {
    pub fn btc() -> Self {
        Self {
            id: CoinId::btc(),
            symbol: "BTC".to_string(),
            min_amount: 546,
        }
    }
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Lp {
    pub shares: u128,
    pub profit: u128,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPoolWithState {
    pub fee_rate: u128,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
    pub state: Option<PoolState>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPool {
    pub states: Vec<PoolState>,
    pub fee_rate: u128,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
}

impl Into<LiquidityPoolWithState> for LiquidityPool {
    fn into(self) -> LiquidityPoolWithState {
        let state = self.states.last().cloned();
        LiquidityPoolWithState {
            fee_rate: self.fee_rate,
            meta: self.meta,
            pubkey: self.pubkey,
            state,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolState {
    pub nonce: u64,
    pub utxo: Utxo,
    // pub rune_utxo: Utxo,
    pub incomes: u128,
    pub untradable: u128,
    pub k: u128,
    pub lp: BTreeMap<String, Lp>,
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

impl Storable for LiquidityPool {
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

impl LiquidityPool {
    pub fn new_empty(meta: CoinMeta, fee_rate: u128, pubkey: Pubkey) -> Option<Self> {
        (fee_rate <= 1_000_000).then(|| ())?;
        Some(Self {
            states: vec![],
            fee_rate,
            meta,
            pubkey,
        })
    }

    pub fn base_id(&self) -> CoinId {
        self.meta.id
    }

    pub(crate) fn charge_fee(btc: u128, per_millis: u128) -> (u128, u128) {
        let charge = btc * per_millis / 1_000_000u128;
        (btc - charge, charge)
    }

    pub(crate) fn liquidity_should_add(
        &self,
        side: CoinBalance,
    ) -> Result<CoinBalance, ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (side.id == btc_meta.id || side.id == self.meta.id)
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        // TODO permit this to add random number as other side
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        if side.id == btc_meta.id {
            // btc -> rune: ∆rune/∆btc = rune/(btc-untradable)
            let rune = side
                .value
                .checked_mul(recent_state.utxo.satoshis as u128)
                .and_then(|m| {
                    m.checked_div(recent_state.utxo.balance.value - recent_state.untradable)
                })
                .filter(|rune| *rune >= self.meta.min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?;
            let new_btc = side.value + recent_state.utxo.satoshis as u128;
            rune.checked_add(recent_state.utxo.balance.value)
                .and_then(|rune| rune.checked_mul(new_btc))
                .ok_or(ExchangeError::Overflow)?;
            Ok(CoinBalance {
                value: rune,
                id: self.meta.id,
            })
        } else {
            // rune -> btc: ∆btc/∆rune = (btc-untradable)/rune
            let btc = side
                .value
                .checked_mul(recent_state.utxo.satoshis as u128 - recent_state.untradable)
                .and_then(|m| m.checked_div(recent_state.utxo.balance.value))
                .filter(|btc| *btc >= btc_meta.min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?;
            let new_btc = btc + recent_state.utxo.satoshis;
            side.value
                .checked_add(recent_state.utxo.balance.value)
                .and_then(|rune| rune.checked_mul(new_btc))
                .ok_or(ExchangeError::Overflow)?;
            Ok(CoinBalance {
                value: btc,
                id: btc_meta.id,
            })
        }
    }

    pub(crate) fn available_to_withdraw(
        &self,
        pubkey_hash: impl AsRef<str>,
    ) -> Result<
        (
            Vec<CoinBalance>,
            u128,
            Option<CoinBalance>,
            Option<CoinBalance>,
        ),
        ExchangeError,
    > {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let lp = recent_state
            .lp
            .get(pubkey_hash.as_ref())
            .map(|r| r.clone())
            .ok_or(ExchangeError::InsufficientFunds)?;
        let btc_supply = recent_state.utxo.satoshis as u128 - recent_state.untradable;
        let rune_supply = recent_state.utxo.balance.value;
        let sqrt_k = crate::sqrt(recent_state.k);

        // take all the profit
        let profit = lp
            .shares
            .checked_mul(recent_state.incomes)
            .and_then(|r| r.checked_div(sqrt_k))
            .and_then(|r| r.checked_add(lp.profit))
            .ok_or(ExchangeError::Overflow)?;
        let btc_delta = lp
            .shares
            .checked_mul(btc_supply)
            .and_then(|r| r.checked_div(sqrt_k))
            .and_then(|r| r.checked_add(profit))
            .filter(|btc| *btc >= CoinMeta::btc().min_amount)
            .ok_or(ExchangeError::TooSmallFunds)?;
        let rune_delta = lp
            .shares
            .checked_mul(rune_supply)
            .and_then(|m| m.checked_div(sqrt_k))
            .filter(|rune| *rune >= self.meta.min_amount)
            .ok_or(ExchangeError::TooSmallFunds)?;
        let btc_remains = btc_supply
            .checked_sub(btc_delta)
            .ok_or(ExchangeError::EmptyPool)?;
        let rune_remains = rune_supply
            .checked_sub(rune_delta)
            .ok_or(ExchangeError::EmptyPool)?;
        // Ok((
        //     CoinBalance {
        //         id: self.meta.id,
        //         value: rune,
        //     },
        //     profit,
        // ))
    }

    /// (x - ∆x)(y + ∆y) = xy
    /// => ∆x = x - xy / (y + ∆y)
    ///    p = ∆y / ∆x
    pub(crate) fn available_to_swap(
        &self,
        taker: CoinBalance,
    ) -> Result<(CoinBalance, u128), ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (taker.id == self.meta.id || taker.id == CoinId::btc())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let btc_supply = recent_state.utxo.satoshis as u128 - recent_state.untradable;
        let rune_supply = recent_state.utxo.balance.value;
        let (offer, fee) = if taker.id == CoinId::btc() {
            // btc -> rune
            let (input_amount, charge) = Self::charge_fee(taker.value, self.fee_rate);
            // TODO improve this to satisfy charge > sign_cost
            (charge > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            let rune_remains = btc_supply
                .checked_add(input_amount)
                .and_then(|sum| recent_state.k.checked_div(sum))
                .ok_or(ExchangeError::InvalidNumeric)?;
            (rune_remains >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let offer = rune_supply - rune_remains;
            (offer > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                CoinBalance {
                    value: offer,
                    id: self.meta.id,
                },
                charge,
            )
        } else {
            // rune -> btc
            let btc_remains = rune_supply
                .checked_add(taker.value)
                .and_then(|sum| recent_state.k.checked_div(sum))
                .ok_or(ExchangeError::InvalidNumeric)?;
            (btc_remains >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let pre_charge = btc_supply - btc_remains;
            let (offer, charge) = Self::charge_fee(pre_charge, self.fee_rate);
            (charge > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (offer >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                CoinBalance {
                    id: btc_meta.id,
                    value: offer,
                },
                charge,
            )
        };
        Ok((offer, fee))
    }

    pub(crate) fn rollback(&mut self, txid: Txid) -> Result<(), ExchangeError> {
        let idx = self
            .states
            .iter()
            .position(|state| state.txid == txid)
            .ok_or(ExchangeError::InvalidState("txid not found".to_string()))?;
        if idx == 0 {
            self.states.clear();
            return Ok(());
        }
        self.states.truncate(idx);
        Ok(())
    }

    pub(crate) fn finalize(&mut self, txid: Txid) -> Result<(), ExchangeError> {
        let idx = self
            .states
            .iter()
            .position(|state| state.txid == txid)
            .ok_or(ExchangeError::InvalidState("txid not found".to_string()))?;
        if idx == 0 {
            return Ok(());
        }
        self.states.rotate_left(idx);
        self.states.truncate(self.states.len() - idx);
        Ok(())
    }

    pub(crate) fn commit(&mut self, state: PoolState) {
        self.states.push(state);
    }
}
