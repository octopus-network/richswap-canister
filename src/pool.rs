use crate::{CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use serde::Serialize;
use std::collections::BTreeMap;

/// represents 0.7/100 = 7/1_000 = 700/1_000_000
pub const DEFAULT_FEE_RATE: u64 = 900;
/// represents 0.2/100 = 2/1_000 = 200/1_000_000
pub const DEFAULT_BURN_RATE: u64 = 100;

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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPoolWithState {
    pub fee_rate: u64,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
    pub addr: String,
    pub tweaked: Pubkey,
    pub state: Option<PoolState>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityPool {
    pub states: Vec<PoolState>,
    pub fee_rate: u64,
    pub burn_rate: u64,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
    pub tweaked: Pubkey,
    pub addr: String,
}

impl Into<LiquidityPoolWithState> for LiquidityPool {
    fn into(self) -> LiquidityPoolWithState {
        let state = self.states.last().cloned();
        LiquidityPoolWithState {
            fee_rate: self.fee_rate,
            meta: self.meta,
            pubkey: self.pubkey,
            tweaked: self.tweaked,
            addr: self.addr,
            state,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
pub struct PoolState {
    pub id: Option<Txid>,
    pub nonce: u64,
    pub utxo: Option<Utxo>,
    pub incomes: u64,
    pub k: u128,
    pub lp: BTreeMap<String, u128>,
}

impl PoolState {
    pub fn satoshis(&self) -> u64 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.satoshis)
            .unwrap_or_default()
    }

    pub fn btc_supply(&self) -> u64 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.satoshis - self.incomes)
            .unwrap_or_default()
    }

    pub fn rune_supply(&self) -> u128 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.balance.value)
            .unwrap_or_default()
    }

    pub fn lp(&self, key: &str) -> u128 {
        self.lp.get(key).copied().unwrap_or_default()
    }
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
    pub fn new_empty(
        meta: CoinMeta,
        fee_rate: u64,
        burn_rate: u64,
        untweaked: Pubkey,
    ) -> Option<Self> {
        (fee_rate <= 1_000_000).then(|| ())?;
        (burn_rate <= 1_000_000).then(|| ())?;
        let tweaked = crate::tweak_pubkey_with_empty(untweaked.clone());
        let addr = tweaked.address();
        Some(Self {
            states: vec![],
            fee_rate,
            burn_rate,
            meta,
            pubkey: untweaked,
            tweaked,
            addr,
        })
    }

    pub fn base_id(&self) -> CoinId {
        self.meta.id
    }

    pub(crate) fn charge_fee(btc: u64, fee_: u64, burn_: u64) -> (u64, u64, u64) {
        let fee = btc * fee_ / 1_000_000u64;
        let burn = btc * burn_ / 1_000_000u64;
        (btc - fee - burn, fee, burn)
    }

    pub(crate) fn liquidity_should_add(
        &self,
        side: CoinBalance,
    ) -> Result<CoinBalance, ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (side.id == btc_meta.id || side.id == self.meta.id)
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        let oppo_id = if side.id == btc_meta.id {
            self.meta.id
        } else {
            btc_meta.id
        };
        if self.states.is_empty() {
            return Ok(CoinBalance {
                value: 0,
                id: oppo_id,
            });
        }
        let recent_state = self.states.last().expect("checked;");
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply();
        if btc_supply == 0 || rune_supply == 0 {
            return Ok(CoinBalance {
                value: 0,
                id: oppo_id,
            });
        }
        if side.id == btc_meta.id {
            let btc_added: u64 = side.value.try_into().expect("BTC amount overflow");
            // btc -> rune: ∆rune = ∆btc * rune / btc
            let rune = side
                .value
                .checked_mul(rune_supply)
                .and_then(|m| m.checked_div(btc_supply as u128))
                // improve this?
                .filter(|rune| *rune >= self.meta.min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?;
            let new_btc = btc_added + btc_supply;
            rune.checked_add(rune_supply)
                .and_then(|rune| rune.checked_mul(new_btc as u128))
                .ok_or(ExchangeError::Overflow)?;
            Ok(CoinBalance {
                value: rune,
                id: self.meta.id,
            })
        } else {
            // rune -> btc: ∆btc = ∆rune * btc / rune
            let btc128 = side
                .value
                .checked_mul(btc_supply as u128)
                .and_then(|m| m.checked_div(rune_supply))
                // improve this?
                .filter(|btc| *btc >= btc_meta.min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?;
            let btc: u64 = btc128.try_into().expect("BTC amount overflow");
            let new_btc = btc + btc_supply;
            side.value
                .checked_add(rune_supply)
                .and_then(|rune| rune.checked_mul(new_btc as u128))
                .ok_or(ExchangeError::Overflow)?;
            Ok(CoinBalance {
                value: btc128,
                id: btc_meta.id,
            })
        }
    }

    pub(crate) fn available_to_withdraw(
        &self,
        pubkey_hash: impl AsRef<str>,
    ) -> Result<(u64, CoinBalance), ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let lp = recent_state.lp(pubkey_hash.as_ref());
        (lp != 0).then(|| ()).ok_or(ExchangeError::LpNotFound)?;
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply();
        let sqrt_k = crate::sqrt(recent_state.k);

        if recent_state.lp.len() > 1 {
            // there are still other lps
            let mut btc_delta: u64 = lp
                .checked_mul(btc_supply as u128)
                .and_then(|r| r.checked_div(sqrt_k))
                // improve this?
                .filter(|btc| *btc >= CoinMeta::btc().min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?
                .try_into()
                .map_err(|_| ExchangeError::Overflow)?;
            let mut rune_delta = lp
                .checked_mul(rune_supply)
                .and_then(|m| m.checked_div(sqrt_k))
                .filter(|rune| *rune >= self.meta.min_amount)
                .ok_or(ExchangeError::TooSmallFunds)?;
            let btc_remains = recent_state
                .satoshis()
                .checked_sub(btc_delta)
                .ok_or(ExchangeError::EmptyPool)?;
            if btc_remains < CoinMeta::btc().min_amount as u64 {
                // reward the dust to the last valid lp
                btc_delta += btc_remains;
                rune_delta = rune_supply;
            }
            Ok((
                btc_delta,
                CoinBalance {
                    id: self.meta.id,
                    value: rune_delta,
                },
            ))
        } else {
            // the last lp
            let btc_remains = recent_state.incomes;
            let btc_delta = if btc_remains < CoinMeta::btc().min_amount as u64 {
                recent_state.satoshis()
            } else {
                recent_state.btc_supply()
            };
            let rune_delta = recent_state
                .utxo
                .as_ref()
                .expect("already checked")
                .balance
                .value;
            Ok((
                btc_delta,
                CoinBalance {
                    id: self.meta.id,
                    value: rune_delta,
                },
            ))
        }
    }

    /// (x - ∆x)(y + ∆y) = xy
    /// => ∆x = x - xy / (y + ∆y)
    ///    p = ∆y / ∆x
    pub(crate) fn available_to_swap(
        &self,
        taker: CoinBalance,
    ) -> Result<(CoinBalance, u64, u64), ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (taker.id == self.meta.id || taker.id == CoinId::btc())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply();
        (btc_supply != 0 && rune_supply != 0)
            .then(|| ())
            .ok_or(ExchangeError::EmptyPool)?;
        if taker.id == CoinId::btc() {
            // btc -> rune
            let input_btc: u64 = taker.value.try_into().expect("BTC amount overflow");
            let (input_amount, fee, burn) =
                Self::charge_fee(input_btc, self.fee_rate, self.burn_rate);
            // TODO improve this to satisfy charge > sign_cost
            (fee > 0 && burn > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            let rune_remains = btc_supply
                .checked_add(input_amount)
                .and_then(|sum| recent_state.k.checked_div(sum as u128))
                .ok_or(ExchangeError::Overflow)?;
            (rune_remains >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let offer = rune_supply - rune_remains;
            (offer > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            Ok((
                CoinBalance {
                    value: offer,
                    id: self.meta.id,
                },
                fee,
                burn,
            ))
        } else {
            // rune -> btc
            let btc_remains = rune_supply
                .checked_add(taker.value)
                .and_then(|sum| recent_state.k.checked_div(sum))
                .ok_or(ExchangeError::Overflow)?;
            // we must ensure that utxo of pool should be >= 546 to hold the dust
            (btc_remains + recent_state.incomes as u128 >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let btc_remains: u64 = btc_remains.try_into().expect("BTC amount overflow");
            let pre_charge = btc_supply - btc_remains;
            let (offer, fee, burn) = Self::charge_fee(pre_charge, self.fee_rate, self.burn_rate);
            (fee > 0 && burn > 0)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            // the user output should be >= 546
            (offer as u128 >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            Ok((
                CoinBalance {
                    id: btc_meta.id,
                    value: offer as u128,
                },
                fee,
                burn,
            ))
        }
    }

    pub(crate) fn rollback(&mut self, txid: Txid) -> Result<(), ExchangeError> {
        let idx = self
            .states
            .iter()
            .position(|state| state.id == Some(txid))
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
            .position(|state| state.id == Some(txid))
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
