use crate::{CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Utxo};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use serde::Serialize;

lazy_static::lazy_static! {
    pub static ref DEFAULT_FEE_RATE: Decimal = Decimal::new(2, 2);
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoinMeta {
    pub id: CoinId,
    pub symbol: String,
    pub min_amount: Decimal,
    pub decimals: u8,
}

impl CoinMeta {
    pub fn btc() -> Self {
        Self {
            id: CoinId::btc(),
            symbol: "BTC".to_string(),
            min_amount: Decimal::new(546, 8),
            decimals: 8,
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPool {
    pub nonce: u64,
    pub btc_utxo: Utxo,
    pub rune_utxo: Utxo,
    pub meta: CoinMeta,
    pub incomes: Decimal,
    pub fee_rate: Decimal,
    pub k: Decimal,
    pub pubkey: Pubkey,
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
    pub fn new(meta: CoinMeta, btc: Utxo, rune: Utxo, fee_rate: Decimal, pubkey: Pubkey) -> Self {
        Self {
            nonce: 0,
            btc_utxo: btc,
            rune_utxo: rune,
            meta,
            incomes: Decimal::zero(),
            fee_rate,
            k: Decimal::zero(),
            pubkey,
        }
    }

    pub fn base_id(&self) -> CoinId {
        self.meta.id
    }

    pub(crate) fn liquidity_should_add(
        &self,
        side: CoinBalance,
    ) -> Result<CoinBalance, ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (side.id == btc_meta.id || side.id == self.meta.id)
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        if side.id == btc_meta.id {
            side.decimal(btc_meta.decimals)
                .map(|btc| (self.k / btc).truncate(self.meta.decimals))
                .filter(|rune| *rune >= self.meta.min_amount)
                .map(|rune| CoinBalance::from_decimal(rune, self.meta.decimals, self.meta.id))
                .ok_or(ExchangeError::TooSmallFunds)
        } else {
            side.decimal(self.meta.decimals)
                .map(|rune| (self.k / rune).truncate(btc_meta.decimals))
                .filter(|btc| *btc >= btc_meta.min_amount)
                .map(|btc| CoinBalance::from_decimal(btc, btc_meta.decimals, btc_meta.id))
                .ok_or(ExchangeError::TooSmallFunds)
        }
    }

    /// (x - ∆x)(y + ∆y) = xy
    /// => ∆x = x - xy / (y + ∆y)
    ///    p = ∆y / ∆x
    pub(crate) fn available_to_swap(
        &self,
        taker: CoinBalance,
    ) -> Result<(CoinBalance, Decimal), ExchangeError> {
        let btc_meta = CoinMeta::btc();
        (taker.id == self.meta.id || taker.id == CoinId::btc())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        let btc_supply = self
            .btc_utxo
            .balance
            .decimal(btc_meta.decimals)
            .ok_or(ExchangeError::InvalidPool)?;
        let rune_supply = self
            .rune_utxo
            .balance
            .decimal(self.meta.decimals)
            .ok_or(ExchangeError::InvalidPool)?;
        let (offer, fee) = if taker.id == CoinId::btc() {
            // btc -> rune
            let taker_amount = taker
                .decimal(btc_meta.decimals)
                .ok_or(ExchangeError::InvalidNumeric)?;
            let charge = (taker_amount * self.fee_rate).truncate(btc_meta.decimals);
            (charge > Decimal::zero())
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            let input_amount = taker_amount - charge;
            let rune_remains = (self.k / (btc_supply + input_amount)).truncate(self.meta.decimals);
            (rune_remains >= self.meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let offer = (rune_supply - rune_remains).truncate(self.meta.decimals);
            (offer > Decimal::zero())
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                CoinBalance::from_decimal(offer, self.meta.decimals, self.meta.id),
                charge,
            )
        } else {
            // rune -> btc
            let taker_amount = taker
                .decimal(self.meta.decimals)
                .ok_or(ExchangeError::InvalidNumeric)?;
            let btc_remains = (self.k / (rune_supply + taker_amount)).truncate(btc_meta.decimals);
            (btc_remains >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::EmptyPool)?;
            let pre_charge = (btc_supply - btc_remains).truncate(btc_meta.decimals);
            let charge = (pre_charge * self.fee_rate).truncate(btc_meta.decimals);
            (charge > Decimal::zero())
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            let offer = pre_charge - charge;
            (offer >= btc_meta.min_amount)
                .then(|| ())
                .ok_or(ExchangeError::TooSmallFunds)?;
            (
                CoinBalance::from_decimal(offer, btc_meta.decimals, btc_meta.id),
                charge,
            )
        };
        Ok((offer, fee))
    }
}
