use crate::ExchangeError;
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use ree_types::{
    bitcoin::{Address, Network},
    CoinBalance, CoinId, InputCoin, OutputCoin, Pubkey, Txid, Utxo,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// represents 0.7/100 = 7/1_000 = 7000/1_000_000
pub const DEFAULT_FEE_RATE: u64 = 7000;
/// represents 0.2/100 = 2/1_000 = 2000/1_000_000
pub const DEFAULT_BURN_RATE: u64 = 2000;
/// each tx's satoshis should be >= 10000
pub const MIN_BTC_VALUE: u64 = 10000;

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
pub struct LiquidityPool {
    pub states: Vec<PoolState>,
    pub fee_rate: u64,
    pub burn_rate: u64,
    pub meta: CoinMeta,
    pub pubkey: Pubkey,
    pub tweaked: Pubkey,
    pub addr: String,
}

impl LiquidityPool {
    pub fn attrs(&self) -> String {
        let attr = serde_json::json!({
            "fee_rate": self.fee_rate,
            "burn_rate": self.burn_rate,
            "tweaked": self.tweaked.to_string(),
            "incomes": self.states.last().map(|state| state.incomes).unwrap_or_default(),
            "sqrt_k": self.states.last().map(|state| state.total_share()).unwrap_or_default(),
        });
        serde_json::to_string(&attr).expect("failed to serialize")
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
        self.utxo.as_ref().map(|utxo| utxo.sats).unwrap_or_default()
    }

    pub fn btc_supply(&self) -> u64 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.sats - self.incomes)
            .unwrap_or_default()
    }

    pub fn rune_supply(&self) -> u128 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.rune_amount())
            .unwrap_or_default()
    }

    pub fn lp(&self, key: &str) -> u128 {
        self.lp.get(key).copied().unwrap_or_default()
    }

    pub fn total_share(&self) -> u128 {
        crate::sqrt(self.k)
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
        let key = ree_types::bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            tweaked.to_x_only_public_key(),
        );
        cfg_if::cfg_if! {
            if #[cfg(feature = "testnet")] {
                let addr = Address::p2tr_tweaked(key, Network::Testnet4);
            } else {
                let addr = Address::p2tr_tweaked(key, Network::Bitcoin);
            }
        }
        Some(Self {
            states: vec![],
            fee_rate,
            burn_rate,
            meta,
            pubkey: untweaked,
            tweaked,
            addr: addr.to_string(),
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
                .filter(|rune| *rune >= self.meta.min_amount)
                .ok_or(ExchangeError::EmptyPool)?;
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
                .ok_or(ExchangeError::Overflow)?;
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

    pub(crate) fn validate_adding_liquidity(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<String>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
        initiator: String,
    ) -> Result<(PoolState, Option<Utxo>), ExchangeError> {
        (input_coins.len() == 2 && output_coins.is_empty())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output_coins, add_liquidity requires 2 inputs and 0 output"
                    .to_string(),
            ))?;
        let x = input_coins[0].coin.clone();
        let y = input_coins[1].coin.clone();
        let mut state = self.states.last().cloned().unwrap_or_default();
        // check nonce matches
        (state.nonce == nonce)
            .then(|| ())
            .ok_or(ExchangeError::PoolStateExpired(state.nonce))?;
        // check prev_outpoint matches
        let pool_utxo = state.utxo.clone();
        (pool_utxo.as_ref().map(|u| u.outpoint()).as_ref() == pool_utxo_spend.last())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_spend/pool state mismatch".to_string(),
            ))?;
        // check output exists
        let pool_new_outpoint = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        // check input coins
        let (btc_input, rune_input) = if x.id == CoinId::btc() && y.id != CoinId::btc() {
            Ok((x, y))
        } else if x.id != CoinId::btc() && y.id == CoinId::btc() {
            Ok((y, x))
        } else {
            Err(ExchangeError::InvalidSignPsbtArgs(
                "Invalid inputs: requires 2 different input coins".to_string(),
            ))
        }?;
        // check minimal liquidity
        (btc_input.value >= MIN_BTC_VALUE as u128)
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        // y = f(x), x' = f(y'); => x == x' || y == y'
        let rune_expecting = self.liquidity_should_add(btc_input)?;
        let btc_expecting = self.liquidity_should_add(rune_input)?;
        // the pool should accept arbitrary numbers
        if rune_expecting.value != 0 {
            // follow the current k
            (rune_expecting == rune_input || btc_expecting == btc_input)
                .then(|| ())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "inputs mismatch with pre_add_liquidity".to_string(),
                ))?;
        } else {
            // arbitrary RUNE number
            (rune_input.value >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "min RUNE amount requires to add liquidity".to_string(),
                ))?;
        }
        // calculate the pool state
        let sats_input: u64 = btc_input
            .value
            .try_into()
            .map_err(|_| ExchangeError::Overflow)?;
        let (btc_pool, rune_pool) = pool_utxo
            .as_ref()
            .map(|u| (u.sats, u.rune_amount()))
            .unwrap_or((0u64, 0u128));
        let (btc_output, rune_output) = (
            btc_pool
                .checked_add(sats_input)
                .ok_or(ExchangeError::Overflow)?,
            rune_pool
                .checked_add(rune_input.value)
                .ok_or(ExchangeError::Overflow)?,
        );
        let user_mint = crate::sqrt(
            rune_input
                .value
                .checked_mul(btc_input.value)
                .ok_or(ExchangeError::Overflow)?,
        );
        let pool_output = Utxo::try_from(
            pool_new_outpoint,
            Some(CoinBalance {
                value: rune_output,
                id: rune_input.id,
            }),
            btc_output,
        )
        .map_err(|_| ExchangeError::InvalidTxid)?;
        state.utxo = Some(pool_output);
        state
            .lp
            .entry(initiator)
            .and_modify(|v| *v += user_mint)
            .or_insert(user_mint);
        state.k = state.rune_supply() * state.btc_supply() as u128;
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, pool_utxo))
    }

    pub(crate) fn available_to_extract(&self) -> Result<u64, ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        // ensure the incomes could be extracted
        (recent_state.incomes >= CoinMeta::btc().min_amount as u64)
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        let btc_supply = recent_state.btc_supply();
        let incomes = if btc_supply < CoinMeta::btc().min_amount as u64 {
            recent_state.incomes + btc_supply
        } else {
            recent_state.incomes
        };
        Ok(incomes)
    }

    pub fn validate_extract_fee(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<String>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.is_empty() && output_coins.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, extract fee requires 0 input and 1 output".to_string(),
            ))?;
        let output = output_coins.first().clone().expect("checked;qed");
        let fee_collector = crate::p2tr_untweaked(&crate::get_fee_collector());
        (output.coin.id == CoinMeta::btc().id && output.to == fee_collector)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(format!(
                "invalid output coin, extract fee requires 1 output of BTC to {}",
                fee_collector
            )))?;
        let mut state = self
            .states
            .last()
            .cloned()
            .ok_or(ExchangeError::EmptyPool)?;
        // check nonce
        (state.nonce == nonce)
            .then(|| ())
            .ok_or(ExchangeError::PoolStateExpired(state.nonce))?;
        let prev_outpoint =
            pool_utxo_spend
                .last()
                .map(|s| s.clone())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_spend not found".to_string(),
                ))?;
        let prev_utxo = state.utxo.clone().ok_or(ExchangeError::EmptyPool)?;
        (prev_outpoint == prev_utxo.outpoint()).then(|| ()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_spend/pool state mismatch".to_string()),
        )?;
        let btc_delta = self.available_to_extract()?;
        (output.coin.value == btc_delta as u128).then(|| ()).ok_or(
            ExchangeError::InvalidSignPsbtArgs(
                "invalid output coin, extract fee requires 1 output of BTC with correct value"
                    .to_string(),
            ),
        )?;
        let pool_output = if btc_delta == prev_utxo.sats {
            None
        } else {
            Some(
                Utxo::try_from(
                    pool_utxo_receive
                        .last()
                        .ok_or(ExchangeError::InvalidSignPsbtArgs(
                            "pool_utxo_receive not found".to_string(),
                        ))?,
                    Some(CoinBalance {
                        id: self.base_id(),
                        value: prev_utxo.rune_amount(),
                    }),
                    prev_utxo.sats - btc_delta,
                )
                .map_err(|_| ExchangeError::InvalidTxid)?,
            )
        };
        state.utxo = pool_output;
        if state.utxo.is_none() {
            state.lp.clear();
        }
        state.incomes = 0;
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, prev_utxo))
    }

    pub(crate) fn available_to_withdraw(
        &self,
        pubkey_hash: impl AsRef<str>,
        share: u128,
    ) -> Result<(u64, CoinBalance, u128), ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let user_total_share = recent_state.lp(pubkey_hash.as_ref());
        (share <= user_total_share)
            .then(|| ())
            .ok_or(ExchangeError::InsufficientFunds)?;

        // global
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply();

        let mut rune_delta = share
            .checked_mul(rune_supply)
            .and_then(|m| m.checked_div(recent_state.total_share()))
            .ok_or(ExchangeError::EmptyPool)?;
        let mut btc_delta = share
            .checked_mul(btc_supply as u128)
            .and_then(|m| m.checked_div(recent_state.total_share()))
            .ok_or(ExchangeError::EmptyPool)?;

        let btc_remains = recent_state
            .satoshis()
            .checked_sub(btc_delta.try_into().map_err(|_| ExchangeError::Overflow)?)
            .ok_or(ExchangeError::EmptyPool)?;
        if btc_remains < CoinMeta::btc().min_amount as u64 {
            // reward the dust to the last valid lp
            btc_delta += btc_remains as u128;
            rune_delta = rune_supply;
        }
        Ok((
            btc_delta.try_into().map_err(|_| ExchangeError::Overflow)?,
            CoinBalance {
                id: self.meta.id,
                value: rune_delta,
            },
            user_total_share - share,
        ))
    }

    pub(crate) fn validate_withdrawing_liquidity(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<String>,
        share: u128,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
        initiator: String,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.is_empty() && output_coins.len() == 2)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output_coins, withdraw_liquidity requires 0 input and 2 outputs"
                    .to_string(),
            ))?;
        let x = output_coins[0].coin.clone();
        let y = output_coins[1].coin.clone();
        let (btc_output, rune_output) = if x.id == CoinId::btc() && y.id != CoinId::btc() {
            Ok((x, y))
        } else if x.id != CoinId::btc() && y.id == CoinId::btc() {
            Ok((y, x))
        } else {
            Err(ExchangeError::InvalidSignPsbtArgs(
                "Invalid outputs: requires 2 different output coins".to_string(),
            ))
        }?;
        let pool_prev_outpoint =
            pool_utxo_spend
                .last()
                .map(|s| s.clone())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_spend not found".to_string(),
                ))?;
        let mut state = self.states.last().ok_or(ExchangeError::EmptyPool)?.clone();
        // check nonce
        (state.nonce == nonce)
            .then(|| ())
            .ok_or(ExchangeError::PoolStateExpired(state.nonce))?;
        // check prev state
        let prev_utxo = state.utxo.clone().ok_or(ExchangeError::EmptyPool)?;
        (prev_utxo.outpoint() == pool_prev_outpoint)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_spend/pool_state don't match".to_string(),
            ))?;
        // check minial sats
        (btc_output.value >= MIN_BTC_VALUE as u128)
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        // check params
        let btc_output_sats: u64 = btc_output
            .value
            .try_into()
            .map_err(|_| ExchangeError::Overflow)?;

        let (btc_expecting, rune_expecting, new_share) =
            self.available_to_withdraw(&initiator, share)?;
        (rune_expecting == rune_output && btc_expecting == btc_output_sats)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "inputs mismatch with pre_withdraw_liquidity".to_string(),
            ))?;

        let (pool_btc_output, pool_rune_output) = (
            prev_utxo
                .sats
                .checked_sub(btc_output_sats)
                .ok_or(ExchangeError::Overflow)?,
            prev_utxo
                .rune_amount()
                .checked_sub(rune_output.value)
                .ok_or(ExchangeError::Overflow)?,
        );
        let pool_should_receive = pool_btc_output != 0 || pool_rune_output != 0;
        let new_utxo = if pool_should_receive {
            Some(
                Utxo::try_from(
                    pool_utxo_receive
                        .last()
                        .ok_or(ExchangeError::InvalidSignPsbtArgs(
                            "pool_utxo_receive not found".to_string(),
                        ))?,
                    Some(CoinBalance {
                        id: rune_output.id,
                        value: pool_rune_output,
                    }),
                    pool_btc_output,
                )
                .map_err(|_| ExchangeError::InvalidTxid)?,
            )
        } else {
            None
        };
        state.utxo = new_utxo;
        state.k = state.rune_supply() * state.btc_supply() as u128;
        if state.utxo.is_none() {
            state.incomes = 0;
            state.lp.clear();
        } else {
            if new_share != 0 {
                state.lp.insert(initiator, new_share);
            } else {
                state.lp.remove(&initiator);
            }
        }
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, prev_utxo))
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
        let k = recent_state.btc_supply() as u128 * recent_state.rune_supply();
        if taker.id == CoinId::btc() {
            // btc -> rune
            let input_btc: u64 = taker.value.try_into().expect("BTC amount overflow");
            let (input_amount, fee, burn) =
                Self::charge_fee(input_btc, self.fee_rate, self.burn_rate);
            let rune_remains = btc_supply
                .checked_add(input_amount)
                .and_then(|sum| k.checked_div(sum as u128))
                .ok_or(ExchangeError::Overflow)?;
            (rune_remains >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let offer = rune_supply - rune_remains;
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
            let pool_btc_remains = rune_supply
                .checked_add(taker.value)
                .and_then(|sum| k.checked_div(sum))
                .ok_or(ExchangeError::Overflow)?;
            let min_hold = CoinMeta::btc().min_amount as u64;
            let pool_btc_remains: u64 = pool_btc_remains.try_into().expect("BTC amount overflow");
            let pre_charge = btc_supply - pool_btc_remains;
            let (offer, fee, burn) = Self::charge_fee(pre_charge, self.fee_rate, self.burn_rate);
            // this is the actual remains
            let pool_btc_remains = btc_supply - offer - burn;
            // plus this to ensure the pool remains >= 546
            let round_to_keep = if pool_btc_remains < min_hold {
                min_hold - pool_btc_remains
            } else {
                0
            };
            Ok((
                CoinBalance {
                    id: btc_meta.id,
                    value: (offer - round_to_keep) as u128,
                },
                fee + round_to_keep,
                burn,
            ))
        }
    }

    pub(crate) fn validate_swap(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<String>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.len() == 1 && output_coins.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, swap requires 1 input and 1 output".to_string(),
            ))?;
        let input = input_coins.first().clone().expect("checked;qed");
        let output = output_coins.first().clone().expect("checked;qed");
        let mut state = self
            .states
            .last()
            .cloned()
            .ok_or(ExchangeError::EmptyPool)?;
        // check nonce
        (state.nonce == nonce)
            .then(|| ())
            .ok_or(ExchangeError::PoolStateExpired(state.nonce))?;
        let prev_outpoint =
            pool_utxo_spend
                .last()
                .map(|s| s.clone())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_spend not found".to_string(),
                ))?;
        let prev_utxo = state.utxo.clone().ok_or(ExchangeError::EmptyPool)?;
        (prev_outpoint == prev_utxo.outpoint()).then(|| ()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_spend/pool state mismatch".to_string()),
        )?;
        // check minimal sats
        let (offer, _, burn) = self.available_to_swap(input.coin)?;
        let (btc_output, rune_output) = if input.coin.id == CoinId::btc() {
            let input_btc: u64 = input
                .coin
                .value
                .try_into()
                .map_err(|_| ExchangeError::Overflow)?;
            (input_btc >= MIN_BTC_VALUE)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            // assume the user inputs were valid
            (
                prev_utxo.sats.checked_add(input_btc),
                prev_utxo.rune_amount().checked_sub(offer.value),
            )
        } else {
            let output_btc: u64 = offer
                .value
                .try_into()
                .map_err(|_| ExchangeError::Overflow)?;
            (output_btc >= MIN_BTC_VALUE)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                prev_utxo.sats.checked_sub(output_btc),
                prev_utxo.rune_amount().checked_add(input.coin.value),
            )
        };
        // check params
        (output.coin == offer)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "inputs mismatch with pre_swap".to_string(),
            ))?;
        let (btc_output, rune_output) = (
            btc_output.ok_or(ExchangeError::Overflow)?,
            rune_output.ok_or(ExchangeError::Overflow)?,
        );
        let pool_output = Utxo::try_from(
            pool_utxo_receive
                .last()
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_receive not found".to_string(),
                ))?,
            Some(CoinBalance {
                id: self.base_id(),
                value: rune_output,
            }),
            btc_output,
        )
        .map_err(|_| ExchangeError::InvalidTxid)?;
        state.utxo = Some(pool_output);
        state.nonce += 1;
        state.incomes += burn;
        // DON'T UPDATE K HERE
        state.id = Some(txid);
        Ok((state, prev_utxo))
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
