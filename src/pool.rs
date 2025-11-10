use crate::ExchangeError;
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use ree_types::{
    bitcoin::{Address, Network},
    CoinBalance, CoinBalances, CoinId, InputCoin, OutputCoin, Pubkey, Txid, Utxo,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

/// represents 0.007
pub const DEFAULT_LP_FEE_RATE: u64 = 7000;
/// represents 0.002
pub const DEFAULT_PROTOCOL_FEE_RATE: u64 = 2000;
/// each tx's satoshis should be >= 10000
pub const MIN_BTC_VALUE: u64 = 10000;
/// each tx's staoshis should be <= 10000000;
pub const MAX_BTC_VALUE: u64 = 10_000_000;

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

/// The `PoolTemplate::Onetime` rule:
/// - only allow add liquidity once
/// - lock_time must be u32::MAX
/// - dynamic fee rate?
/// - only created by governance
#[derive(Clone, Copy, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PoolTemplate {
    #[serde(rename = "standard")]
    Standard,
    #[serde(rename = "onetime")]
    Onetime,
}

impl Default for PoolTemplate {
    fn default() -> Self {
        PoolTemplate::Standard
    }
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeAdjustMechanism {
    pub start_at: u64,
    pub decr_interval_ms: u64,
    pub rate_decr_step: u64,
    pub min_rate: u64,
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
    #[serde(default)]
    pub fee_adjust_mechanism: Option<FeeAdjustMechanism>,
}

impl LiquidityPool {
    pub fn attrs(&self) -> String {
        let attr = serde_json::json!({
            "tweaked_key": self.tweaked.to_string(),
            "key_derive_path": vec![self.base_id().to_bytes()],
            "lp_fee_rate": self.get_lp_fee(),
            "protocol_fee_rate": self.burn_rate,
            "lp_revenue": self.states.last().map(|state| state.lp_earnings.values().map(|v| *v).sum::<u64>()).unwrap_or_default(),
            "protocol_revenue": self.states.last().map(|state| state.incomes).unwrap_or_default(),
            "sqrt_k": self.states.last().map(|state| state.k).unwrap_or_default(),
            "total_btc_donation": self.states.last().map(|state| state.total_btc_donation).unwrap_or_default(),
            "total_rune_donation": self.states.last().map(|state| state.total_rune_donation).unwrap_or_default(),
            "template": self.fee_adjust_mechanism.map(|_| PoolTemplate::Onetime).unwrap_or(PoolTemplate::Standard),
            "fee_adjust_mechanism": self.fee_adjust_mechanism,
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
    pub lp_earnings: BTreeMap<String, u64>,
    pub total_btc_donation: u64,
    pub total_rune_donation: u128,
    #[serde(default)]
    pub lp_locks: BTreeMap<String, u32>,
    #[serde(default)]
    pub locked_lp_revenue: BTreeMap<String, u64>,
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Liquidity {
    pub user_incomes: u64,
    pub user_share: u128,
    pub locked_revenue: u64,
    pub total_share: u128,
    pub lock_until: u32,
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

    pub fn rune_supply(&self, id: &CoinId) -> u128 {
        self.utxo
            .as_ref()
            .map(|utxo| utxo.coins.value_of(id))
            .unwrap_or_default()
    }

    pub fn lp(&self, key: &str) -> Liquidity {
        let lock_until = self.lp_locks.get(key).copied().unwrap_or_default();
        // if the lock_until is in the past, set it to 0
        Liquidity {
            user_incomes: self.lp_earnings.get(key).copied().unwrap_or_default(),
            user_share: self.lp.get(key).copied().unwrap_or_default(),
            locked_revenue: self.locked_lp_revenue.get(key).copied().unwrap_or_default(),
            total_share: self.k,
            lock_until,
        }
    }

    pub(crate) fn charge_fee(
        &self,
        btc: u64,
        fee_: u64,
        burn_: u64,
    ) -> Result<(u64, u64, u64, u64), ExchangeError> {
        let max_block = crate::get_max_block().ok_or(ExchangeError::BlockSyncing)?;
        let total_locked = self
            .lp_locks
            .iter()
            .filter(|(_, v)| **v > max_block.block_height)
            .map(|(k, _)| self.lp.get(k.as_str()).copied().unwrap_or_default())
            .sum();
        let fee = btc * fee_ / 1_000_000u64;
        let locked_fee = (fee as u128)
            .checked_mul(total_locked)
            .and_then(|v| v.checked_div(self.k))
            .ok_or(ExchangeError::Overflow)?;
        let locked_fee = locked_fee.try_into().map_err(|_| ExchangeError::Overflow)?;
        let burn = btc * burn_ / 1_000_000u64;
        Ok((btc - fee - burn, fee - locked_fee, locked_fee, burn))
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
        mechanism: Option<FeeAdjustMechanism>,
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
            fee_adjust_mechanism: mechanism,
        })
    }

    pub fn base_id(&self) -> CoinId {
        self.meta.id
    }

    pub fn get_lp_fee(&self) -> u64 {
        match self.fee_adjust_mechanism {
            Some(mechanism) => {
                let current_ms = ic_cdk::api::time() / 1_000_000;
                let decr = (current_ms - mechanism.start_at) / mechanism.decr_interval_ms
                    * mechanism.rate_decr_step;
                let decr = u64::min(decr, self.fee_rate - mechanism.min_rate);
                self.fee_rate - decr
            }
            None => self.fee_rate,
        }
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
        let rune_supply = recent_state.rune_supply(&self.meta.id);
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
        &mut self,
        txid: Txid,
        nonce: u64,
        mut lock_time: u32,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
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
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let x = input_coins[0].coin.clone();
        let y = input_coins[1].coin.clone();
        // check if `onetime` pool
        if let Some(mut mechanism) = self.fee_adjust_mechanism {
            (self.states.is_empty())
                .then(|| ())
                .ok_or(ExchangeError::OnetimePool)?;
            lock_time = u32::MAX;
            mechanism.start_at = ic_cdk::api::time() / 1_000_000;
        }

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
        (btc_input.value >= crate::min_sats() as u128)
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
            .map(|u| (u.sats, u.coins.value_of(&self.meta.id)))
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
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        (pool_output.sats == btc_output
            && pool_output.coins.value_of(&self.meta.id) == rune_output)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_add_liquidity".to_string(),
            ))?;
        if lock_time > 0 {
            (lock_time >= crate::min_lock_time())
                .then_some(())
                .ok_or(ExchangeError::InvalidLockMessage)?;
            let max_block = crate::get_max_block().ok_or(ExchangeError::BlockSyncing)?;
            let lock_until = max_block
                .block_height
                .checked_add(lock_time)
                .unwrap_or(u32::MAX);
            state
                .lp_locks
                .entry(initiator.clone())
                .and_modify(|t| {
                    if *t < lock_until {
                        *t = lock_until;
                    }
                })
                .or_insert(lock_until);
        }
        state.utxo = Some(pool_output);
        state
            .lp
            .entry(initiator)
            .and_modify(|v| *v += user_mint)
            .or_insert(user_mint);
        state.k += user_mint;
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, pool_utxo))
    }

    pub(crate) fn available_to_extract(&self) -> Result<u64, ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        // ensure the incomes could be extracted
        (recent_state.incomes >= crate::min_sats())
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
        pool_utxo_receive: Vec<Utxo>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.is_empty() && output_coins.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, extract fee requires 0 input and 1 output".to_string(),
            ))?;
        (pool_utxo_receive.len() == 1 || pool_utxo_receive.is_empty())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let output = output_coins.first().clone().expect("checked;qed");
        let fee_collector = crate::get_fee_collector();
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
            (pool_utxo_receive.is_empty()).then(|| ()).ok_or(
                ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive should be empty".to_string()),
            )?;
            None
        } else {
            let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
                ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
            )?;
            (pool_output.sats == prev_utxo.sats - btc_delta
                && pool_output.coins.value_of(&self.meta.id)
                    == prev_utxo.coins.value_of(&self.meta.id))
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_extract_fee".to_string(),
            ))?;
            Some(pool_output)
        };
        if state.utxo.is_none() {
            state.lp.clear();
        }
        state.utxo = pool_output;
        state.incomes = 0;
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, prev_utxo))
    }

    pub(crate) fn available_to_claim(
        &self,
        pubkey_hash: impl AsRef<str>,
    ) -> Result<u64, ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let user_revenue = recent_state
            .locked_lp_revenue
            .get(pubkey_hash.as_ref())
            .copied()
            .unwrap_or_default();
        (user_revenue >= crate::min_sats())
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        (user_revenue <= MAX_BTC_VALUE)
            .then(|| ())
            .ok_or(ExchangeError::FundsLimitExceeded)?;
        let btc_remains = recent_state
            .satoshis()
            .checked_sub(user_revenue)
            .ok_or(ExchangeError::EmptyPool)?;
        (btc_remains >= CoinMeta::btc().min_amount as u64)
            .then(|| ())
            .ok_or(ExchangeError::EmptyPool)?;
        Ok(user_revenue)
    }

    pub(crate) fn validate_claiming_revenue(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
        beneficiary: String,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
        _initiator: String,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.is_empty() && output_coins.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, extract fee requires 0 input and 1 output".to_string(),
            ))?;
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let pool_prev_outpoint =
            pool_utxo_spend
                .last()
                .map(|s| s.clone())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_spend not found".to_string(),
                ))?;
        let output = output_coins.first().clone().expect("checked;qed");
        (output.coin.id == CoinMeta::btc().id && output.to == beneficiary)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(format!(
                "invalid output coin, extract fee requires 1 output of BTC to {}",
                beneficiary
            )))?;

        let mut state = self.states.last().ok_or(ExchangeError::EmptyPool)?.clone();
        // check nonce
        (state.nonce == nonce)
            .then(|| ())
            .ok_or(ExchangeError::PoolStateExpired(state.nonce))?;
        // check prev state equals utxo_spend
        let prev_utxo = state.utxo.clone().ok_or(ExchangeError::EmptyPool)?;
        (prev_utxo.outpoint() == pool_prev_outpoint)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_spend/pool_state don't match".to_string(),
            ))?;

        let claim_sats = self.available_to_claim(&beneficiary)?;
        let (pool_btc_output, pool_rune_output) = (
            prev_utxo
                .sats
                .checked_sub(claim_sats)
                .ok_or(ExchangeError::Overflow)?,
            prev_utxo.coins.value_of(&self.meta.id),
        );
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        (pool_output.sats == pool_btc_output
            && pool_output.coins.value_of(&self.meta.id) == pool_rune_output)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_claim_revenue".to_string(),
            ))?;

        state.utxo = Some(pool_output);
        state.locked_lp_revenue.remove(&beneficiary);
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, prev_utxo))
    }

    pub(crate) fn available_to_withdraw(
        &self,
        pubkey_hash: impl AsRef<str>,
        share: u128,
        now: u32,
    ) -> Result<(u64, CoinBalance, u128), ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let lock_until = recent_state
            .lp_locks
            .get(pubkey_hash.as_ref())
            .copied()
            .unwrap_or_default();
        (lock_until < now)
            .then(|| ())
            .ok_or(ExchangeError::LiquidityLocked)?;
        let user_total_share = recent_state
            .lp
            .get(pubkey_hash.as_ref())
            .copied()
            .unwrap_or_default();
        (share <= user_total_share)
            .then(|| ())
            .ok_or(ExchangeError::InsufficientFunds)?;

        // global
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply(&self.meta.id);

        let mut rune_delta = share
            .checked_mul(rune_supply)
            .and_then(|m| m.checked_div(recent_state.k))
            .ok_or(ExchangeError::EmptyPool)?;
        let mut btc_delta = share
            .checked_mul(btc_supply as u128)
            .and_then(|m| m.checked_div(recent_state.k))
            .ok_or(ExchangeError::EmptyPool)?;
        (btc_delta <= MAX_BTC_VALUE as u128)
            .then(|| ())
            .ok_or(ExchangeError::FundsLimitExceeded)?;
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
        pool_utxo_receive: Vec<Utxo>,
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
        (pool_utxo_receive.len() == 1 || pool_utxo_receive.is_empty())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
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
        (btc_output.value >= crate::min_sats() as u128)
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        // check params
        let btc_output_sats: u64 = btc_output
            .value
            .try_into()
            .map_err(|_| ExchangeError::Overflow)?;

        let max_block = crate::get_max_block().ok_or(ExchangeError::BlockSyncing)?;
        let (btc_expecting, rune_expecting, new_share) =
            self.available_to_withdraw(&initiator, share, max_block.block_height)?;
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
                .coins
                .value_of(&self.meta.id)
                .checked_sub(rune_output.value)
                .ok_or(ExchangeError::Overflow)?,
        );
        let pool_should_receive = pool_btc_output != 0 || pool_rune_output != 0;
        let new_utxo = if pool_should_receive {
            let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
                ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
            )?;
            (pool_output.sats == pool_btc_output
                && pool_output.coins.value_of(&self.meta.id) == pool_rune_output)
                .then(|| ())
                .ok_or(ExchangeError::InvalidSignPsbtArgs(
                    "pool_utxo_receive mismatch with pre_withdraw_liquidity".to_string(),
                ))?;
            Some(pool_output)
        } else {
            (pool_utxo_receive.is_empty()).then(|| ()).ok_or(
                ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive should be empty".to_string()),
            )?;
            None
        };
        state.utxo = new_utxo;
        state.k -= share;
        state.lp_locks.remove(&initiator);
        if state.utxo.is_none() {
            state.incomes = 0;
            state.lp.clear();
        } else {
            if new_share != 0 {
                state.lp.insert(initiator, new_share);
            } else {
                state.lp.remove(&initiator);
                state.lp_earnings.remove(&initiator);
            }
        }
        state.nonce += 1;
        state.id = Some(txid);
        Ok((state, prev_utxo))
    }

    pub(crate) fn wish_to_bi_donate(
        &self,
        input_sats: u64,
        input_rune: CoinBalance,
    ) -> Result<(CoinBalance, u64), ExchangeError> {
        if input_rune.id != self.meta.id {
            return Err(ExchangeError::InvalidPool);
        }
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let total_sats = recent_state
            .utxo
            .as_ref()
            .map(|u| u.sats)
            .ok_or(ExchangeError::EmptyPool)?;
        let rune_supply = recent_state.rune_supply(&self.base_id());
        (total_sats != 0 && rune_supply != 0)
            .then(|| ())
            .ok_or(ExchangeError::EmptyPool)?;
        Ok((
            CoinBalance {
                value: rune_supply + input_rune.value,
                id: self.meta.id,
            },
            total_sats + input_sats,
        ))
    }

    pub(crate) fn validate_bi_donate(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.len() == 2 && output_coins.is_empty())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, donate requires 2 inputs and 0 output".to_string(),
            ))?;
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let x = input_coins[0].coin.clone();
        let y = input_coins[1].coin.clone();
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
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let (btc_input, rune_input) = if x.id == CoinId::btc() && y.id != CoinId::btc() {
            Ok((x, y))
        } else if x.id != CoinId::btc() && y.id == CoinId::btc() {
            Ok((y, x))
        } else {
            Err(ExchangeError::InvalidSignPsbtArgs(
                "Invalid inputs: requires 2 different input coins".to_string(),
            ))
        }?;

        let (out_rune, out_sats) = self.wish_to_bi_donate(btc_input.value as u64, rune_input)?;
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        ic_cdk::println!(
            "pool_output: {:?}, out_sats: {}, out_rune({}): {}",
            pool_output,
            out_sats,
            out_rune.id,
            out_rune.value
        );
        (pool_output.sats == out_sats
            && pool_output.coins.value_of(&self.meta.id) == out_rune.value)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_donate".to_string(),
            ))?;
        let new_k = crate::sqrt(out_rune.value * (out_sats - state.incomes) as u128);
        let mut new_lp = BTreeMap::new();
        for (lp, share) in state.lp.iter() {
            new_lp.insert(
                lp.clone(),
                share
                    .checked_mul(new_k)
                    .and_then(|mul| mul.checked_div(state.k))
                    .ok_or(ExchangeError::Overflow)?,
            );
        }
        let k_adjust = new_lp.values().sum();
        state.id = Some(txid);
        state.nonce += 1;
        state.k = k_adjust;
        state.lp = new_lp;
        state.total_btc_donation += btc_input.value as u64;
        state.utxo = Some(pool_output);
        Ok((state, prev_utxo))
    }

    pub(crate) fn wish_to_donate(
        &self,
        input_sats: u64,
    ) -> Result<(CoinBalance, u64), ExchangeError> {
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let total_sats = recent_state
            .utxo
            .as_ref()
            .map(|u| u.sats)
            .ok_or(ExchangeError::EmptyPool)?;
        let rune_supply = recent_state.rune_supply(&self.base_id());
        (total_sats != 0 && rune_supply != 0)
            .then(|| ())
            .ok_or(ExchangeError::EmptyPool)?;
        Ok((
            CoinBalance {
                value: rune_supply,
                id: self.meta.id,
            },
            total_sats + input_sats,
        ))
    }

    pub(crate) fn validate_donate(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (input_coins.len() == 1 && output_coins.is_empty())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, swap requires 1 input and 0 output".to_string(),
            ))?;
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let input = input_coins.first().clone().expect("checked;qed");
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
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        (input.coin.id == CoinId::btc())
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "input coin must be BTC".to_string(),
            ))?;
        let (out_rune, out_sats) = self.wish_to_donate(input.coin.value as u64)?;
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        ic_cdk::println!(
            "pool_output: {:?}, out_sats: {}, out_rune({}): {}",
            pool_output,
            out_sats,
            out_rune.id,
            out_rune.value
        );
        (pool_output.sats == out_sats
            && pool_output.coins.value_of(&self.meta.id) == out_rune.value)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_donate".to_string(),
            ))?;
        let new_k = crate::sqrt(out_rune.value * (out_sats - state.incomes) as u128);
        let mut new_lp = BTreeMap::new();
        for (lp, share) in state.lp.iter() {
            new_lp.insert(
                lp.clone(),
                share
                    .checked_mul(new_k)
                    .and_then(|mul| mul.checked_div(state.k))
                    .ok_or(ExchangeError::Overflow)?,
            );
        }
        let k_adjust = new_lp.values().sum();
        state.id = Some(txid);
        state.nonce += 1;
        state.k = k_adjust;
        state.lp = new_lp;
        state.total_btc_donation += input.coin.value as u64;
        state.utxo = Some(pool_output);
        Ok((state, prev_utxo))
    }

    pub(crate) fn validate_self_donate(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
    ) -> Result<(PoolState, Utxo), ExchangeError> {
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
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
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
            ))?;
        let donate_amount = state.incomes;
        let out_rune = state.rune_supply(&self.base_id());
        let out_sats = state.satoshis();
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        (pool_output.sats == out_sats && pool_output.coins.value_of(&self.base_id()) == out_rune)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch with pre_self_donate".to_string(),
            ))?;
        let new_k = crate::sqrt(out_rune * out_sats as u128);
        let mut new_lp = BTreeMap::new();
        for (lp, share) in state.lp.iter() {
            new_lp.insert(
                lp.clone(),
                share
                    .checked_mul(new_k)
                    .and_then(|mul| mul.checked_div(state.k))
                    .ok_or(ExchangeError::Overflow)?,
            );
        }
        let k_adjust = new_lp.values().sum();
        state.id = Some(txid);
        state.nonce += 1;
        state.k = k_adjust;
        state.lp = new_lp;
        state.incomes = 0;
        state.total_btc_donation += donate_amount;
        state.utxo = Some(pool_output);
        Ok((state, prev_utxo))
    }

    pub(crate) fn merge_rich_protocol_revenue(&mut self) -> Result<(), ExchangeError> {
        if self.addr != crate::get_fee_collector() {
            return Err(ExchangeError::InvalidPool);
        }
        let rune_id = self.base_id();
        let recent_state = self.states.last_mut().ok_or(ExchangeError::EmptyPool)?;
        let new_k = crate::sqrt(
            recent_state.rune_supply(&rune_id)
                * (recent_state.incomes + recent_state.btc_supply()) as u128,
        );
        let mut new_lp = BTreeMap::new();
        for (lp, share) in recent_state.lp.iter() {
            new_lp.insert(
                lp.clone(),
                share
                    .checked_mul(new_k)
                    .and_then(|mul| mul.checked_div(recent_state.k))
                    .ok_or(ExchangeError::Overflow)?,
            );
        }
        let k_adjust = new_lp.values().sum();
        recent_state.k = k_adjust;
        recent_state.lp = new_lp;
        recent_state.total_btc_donation += recent_state.incomes;
        recent_state.incomes = 0;
        Ok(())
    }

    fn ensure_price_limit(
        sats: u64,
        rune: u128,
        sats1: u64,
        rune1: u128,
    ) -> Result<u32, ExchangeError> {
        let sats = sats as i128;
        let sats1 = sats1 as i128;
        let rune = rune as i128;
        let rune1 = rune1 as i128;

        let a = sats * rune1;
        let b = sats1 * rune;

        let a = rust_decimal::Decimal::from_i128_with_scale(a, 0);
        let b = rust_decimal::Decimal::from_i128_with_scale(b, 0);
        let s = b / a;
        let max = rust_decimal::Decimal::new(200, 2);
        let min = rust_decimal::Decimal::new(50, 2);
        (s >= min && s <= max)
            .then(|| ())
            .ok_or(ExchangeError::PriceImpactLimitExceeded)?;
        let p_delta = (s - rust_decimal::Decimal::ONE) * rust_decimal::Decimal::new(10000, 0);
        Ok(p_delta
            .abs()
            .trunc_with_scale(0)
            .normalize()
            .mantissa()
            .try_into()
            .unwrap_or(0) as u32)
    }

    /// (x - ∆x)(y + ∆y) = xy
    /// => ∆x = x - xy / (y + ∆y)
    ///    p = ∆y / ∆x
    pub(crate) fn available_to_swap(
        &self,
        taker: CoinBalance,
    ) -> Result<(CoinBalance, u64, u64, u64, u32), ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (taker.id == self.meta.id || taker.id == CoinId::btc())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        let recent_state = self.states.last().ok_or(ExchangeError::EmptyPool)?;
        let btc_supply = recent_state.btc_supply();
        let rune_supply = recent_state.rune_supply(&self.base_id());
        (btc_supply != 0 && rune_supply != 0)
            .then(|| ())
            .ok_or(ExchangeError::EmptyPool)?;
        let k = recent_state.btc_supply() as u128 * recent_state.rune_supply(&self.base_id());
        if taker.id == CoinId::btc() {
            // btc -> rune
            let input_btc: u64 = taker.value.try_into().expect("BTC amount overflow");
            (input_btc <= MAX_BTC_VALUE as u64)
                .then(|| ())
                .ok_or(ExchangeError::FundsLimitExceeded)?;
            let (input_amount, lp_fee, locked_lp_fee, protocol_fee) =
                recent_state.charge_fee(input_btc, self.fee_rate, self.burn_rate)?;
            let rune_remains = btc_supply
                .checked_add(input_amount)
                .and_then(|sum| k.checked_div(sum as u128))
                .ok_or(ExchangeError::Overflow)?;
            (rune_remains >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let price_impact = Self::ensure_price_limit(
                btc_supply,
                rune_supply,
                btc_supply + input_amount,
                rune_remains,
            )?;
            let offer = rune_supply - rune_remains;
            Ok((
                CoinBalance {
                    value: offer,
                    id: self.meta.id,
                },
                lp_fee,
                locked_lp_fee,
                protocol_fee,
                price_impact,
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
            let (offer, lp_fee, locked_lp_fee, protocol_fee) =
                recent_state.charge_fee(pre_charge, self.fee_rate, self.burn_rate)?;
            // this is the actual remains
            let pool_btc_remains = btc_supply - offer - protocol_fee - locked_lp_fee;
            // plus this to ensure the pool remains >= 546
            let round_to_keep = if pool_btc_remains < min_hold {
                min_hold - pool_btc_remains
            } else {
                0
            };
            let out_sats = offer - round_to_keep;
            (out_sats <= MAX_BTC_VALUE as u64)
                .then(|| ())
                .ok_or(ExchangeError::FundsLimitExceeded)?;
            let price_impact = Self::ensure_price_limit(
                btc_supply,
                rune_supply,
                pool_btc_remains,
                rune_supply + taker.value,
            )?;
            Ok((
                CoinBalance {
                    id: btc_meta.id,
                    value: out_sats as u128,
                },
                lp_fee + round_to_keep,
                locked_lp_fee,
                protocol_fee,
                price_impact,
            ))
        }
    }

    pub(crate) fn validate_swap(
        &self,
        txid: Txid,
        nonce: u64,
        pool_utxo_spend: Vec<String>,
        pool_utxo_receive: Vec<Utxo>,
        input_coins: Vec<InputCoin>,
        output_coins: Vec<OutputCoin>,
    ) -> Result<(PoolState, Utxo, serde_json::Value), ExchangeError> {
        (input_coins.len() == 1 && output_coins.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "invalid input/output coins, swap requires 1 input and 1 output".to_string(),
            ))?;
        (pool_utxo_receive.len() == 1)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive not found".to_string(),
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
        let (offer, lp_fee, locked_lp_fee, protocol_fee, _) = self.available_to_swap(input.coin)?;
        let (btc_output, rune_output) = if input.coin.id == CoinId::btc() {
            let input_btc: u64 = input
                .coin
                .value
                .try_into()
                .map_err(|_| ExchangeError::Overflow)?;
            (input_btc >= crate::min_sats())
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            // assume the user inputs were valid
            (
                prev_utxo.sats.checked_add(input_btc),
                prev_utxo
                    .coins
                    .value_of(&self.meta.id)
                    .checked_sub(offer.value),
            )
        } else {
            let output_btc: u64 = offer
                .value
                .try_into()
                .map_err(|_| ExchangeError::Overflow)?;
            (output_btc >= crate::min_sats())
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                prev_utxo.sats.checked_sub(output_btc),
                prev_utxo
                    .coins
                    .value_of(&self.meta.id)
                    .checked_add(input.coin.value),
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
        let pool_output = pool_utxo_receive.last().map(|s| s.clone()).ok_or(
            ExchangeError::InvalidSignPsbtArgs("pool_utxo_receive not found".to_string()),
        )?;
        (pool_output.sats == btc_output
            && pool_output.coins.value_of(&self.meta.id) == rune_output)
            .then(|| ())
            .ok_or(ExchangeError::InvalidSignPsbtArgs(
                "pool_utxo_receive mismatch".to_string(),
            ))?;
        state.utxo = Some(pool_output);
        // only update
        let max_height = crate::get_max_block()
            .map(|b| b.block_height)
            .unwrap_or_default();
        let total_locked = state
            .lp_locks
            .iter()
            .filter(|(_, v)| **v > max_height)
            .map(|(k, _)| state.lp.get(k.as_str()).copied().unwrap_or_default())
            .sum();

        // locked LPs have extra revenue
        for (k, _) in state.lp_locks.iter().filter(|(_, u)| **u > max_height) {
            // the share means locked/total_locked
            if let Some(fee) = state
                .lp
                .get(k)
                .and_then(|share| share.checked_mul(locked_lp_fee as u128))
                .and_then(|mul| mul.checked_div(total_locked))
            {
                let fee_in_sats = fee as u64;
                state
                    .locked_lp_revenue
                    .entry(k.clone())
                    .and_modify(|e| *e += fee_in_sats)
                    .or_insert(fee_in_sats);
                state
                    .lp_earnings
                    .entry(k.clone())
                    .and_modify(|e| *e += fee_in_sats)
                    .or_insert(fee_in_sats);
            }
        }
        // all LPs share the rest
        for (k, v) in state.lp.iter() {
            if let Some(incr) = (lp_fee as u128)
                .checked_mul(*v)
                .and_then(|mul| mul.checked_div(state.k))
            {
                state
                    .lp_earnings
                    .entry(k.clone())
                    .and_modify(|e| *e += incr as u64)
                    .or_insert(incr as u64);
            }
        }
        state.nonce += 1;
        state.incomes += protocol_fee;
        state.id = Some(txid);
        let log = serde_json::json!({"pool": self.addr, "lp_fee": lp_fee, "protocol_fee": protocol_fee, "locked_lp_fee": locked_lp_fee});
        Ok((state, prev_utxo, log))
    }

    pub(crate) async fn merge_utxos(
        &self,
        inputs: &[Utxo],
        fee_rate: u64,
    ) -> Result<PoolState, ExchangeError> {
        let mut state = self.states.last().ok_or(ExchangeError::EmptyPool)?.clone();
        let (_, out_rune) = crate::calculate_merge_utxos(inputs, self.base_id());
        let mut psbt = crate::construct_psbt(&self.addr, &self.addr, &inputs, fee_rate)?;
        let out_sats = psbt.unsigned_tx.output[0].value.to_sat();
        for utxo in inputs {
            crate::psbt::sign(&mut psbt, &utxo, self.meta.id.to_bytes())
                .await
                .inspect_err(|e| ic_cdk::println!("sign error: {}", e))
                .map_err(|_| ExchangeError::ChainKeyError)?;
        }
        let new_k = crate::sqrt(out_rune.value * (out_sats - state.incomes) as u128);
        let mut new_lp = BTreeMap::new();
        for (lp, share) in state.lp.iter() {
            new_lp.insert(
                lp.clone(),
                share
                    .checked_mul(new_k)
                    .and_then(|mul| mul.checked_div(state.k))
                    .ok_or(ExchangeError::Overflow)?,
            );
        }
        let k_adjust = new_lp.values().sum();
        let txid = Txid::from_str(&psbt.unsigned_tx.compute_txid().to_string()).unwrap();
        let mut coins = CoinBalances::new();
        coins.add_coin(&out_rune);
        let output = Utxo {
            txid: txid.clone(),
            vout: 0,
            sats: out_sats,
            coins,
        };
        crate::send_transaction(&psbt.extract_tx().expect("shouldn't fail"))
            .await
            .inspect_err(|e| ic_cdk::println!("send transaction error: {}", e))
            .map_err(|_| ExchangeError::FetchBitcoinCanisterError)?;
        state.id = Some(txid);
        state.nonce += 1;
        state.k = k_adjust;
        state.lp = new_lp;
        state.utxo = Some(output);
        Ok(state)
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

#[test]
pub fn test_price_limit() {
    // 1:1, p = 1
    let sats = 1000;
    let rune = 1000;
    // 1.1:0.9, p = 11/9 > 110%
    let sats1 = 1100;
    let rune1 = 900;
    assert!(LiquidityPool::ensure_price_limit(sats, rune, sats1, rune1).is_err());

    // 10:1, p = 10
    let sats = 1000;
    let rune = 100;
    // 11:1, p = 11
    let sats1 = 1100;
    let rune1 = 100;
    // delta = (11 - 10)/10 = 10%
    let delta = LiquidityPool::ensure_price_limit(sats, rune, sats1, rune1);
    assert!(delta.is_ok());
    assert_eq!(delta.unwrap(), 1000);

    // 1:10, p = 1/10 = 0.1
    let sats = 100;
    let rune = 1000;
    // 1:11, p = 1/11 = 0.09090909
    let sats1 = 100;
    let rune1 = 1100;
    // delta = 9%
    let delta = LiquidityPool::ensure_price_limit(sats, rune, sats1, rune1);
    assert!(delta.is_ok());
    assert_eq!(delta.unwrap(), 909);
}

#[test]
pub fn test_fee_adjust() {
    let mechanism = FeeAdjustMechanism {
        start_at: 1761368803654,
        decr_interval_ms: 10 * 60 * 1000,
        rate_decr_step: 10_000,
        min_rate: 100_000,
    };
    let current_ms = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let decr =
        (current_ms - mechanism.start_at) / mechanism.decr_interval_ms * mechanism.rate_decr_step;
    let decr = u64::min(decr, 990_000 - mechanism.min_rate);
    let fee_rate = 990_000 - decr;
    assert_eq!(fee_rate, 100_000);
}
