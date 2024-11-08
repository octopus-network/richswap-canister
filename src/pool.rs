use crate::{CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Utxo};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{storable::Bound, Storable};
use serde::Serialize;

const K_MAX_SCALE: u8 = 18;

lazy_static::lazy_static! {
    pub static ref DEFAULT_FEE_RATE: Decimal = Decimal::new(2, 2);
}

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SwapOffer {
    pub maker_input: Vec<Utxo>,
    pub outputs: Vec<Output>,
    pub tx_fee: Decimal,
    pub price: Decimal,
}

#[derive(Debug, Eq, PartialEq, Clone, CandidType, Deserialize, Serialize)]
pub struct SwapQuery {
    pub pubkey: Pubkey,
    pub balance: CoinBalance,
}

#[derive(Clone, CandidType, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoinMeta {
    pub id: CoinId,
    pub symbol: String,
    pub min_amount: Decimal,
    pub decimals: u8,
}

impl CoinMeta {
    pub fn validate(&self) -> Result<(), ExchangeError> {
        if self.id == CoinId::btc() {
            (self.decimals == 8)
                .then(|| ())
                .ok_or(ExchangeError::InvalidPool)?;
            (self.min_amount == Decimal::new(546, 8))
                .then(|| ())
                .ok_or(ExchangeError::InvalidPool)?;
            (self.symbol == "BTC")
                .then(|| ())
                .ok_or(ExchangeError::InvalidPool)?;
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPool {
    pub x_utxo: Option<Utxo>,
    pub y_utxo: Option<Utxo>,
    pub x_meta: CoinMeta,
    pub y_meta: CoinMeta,
    pub y_incomes: Decimal,
    pub x_incomes: Decimal,
    pub tx_fee_rate: Decimal,
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
        let dire =
            ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode LiquidityPool");
        dire
    }
}

impl LiquidityPool {
    pub fn new(x_meta: CoinMeta, y_meta: CoinMeta, tx_fee_rate: Decimal, pubkey: Pubkey) -> Self {
        Self {
            x_utxo: None,
            y_utxo: None,
            x_meta,
            y_meta,
            y_incomes: Decimal::zero(),
            x_incomes: Decimal::zero(),
            tx_fee_rate,
            k: Decimal::zero(),
            pubkey,
        }
    }

    pub fn base_id(&self) -> CoinId {
        if self.x_meta.id == CoinId::btc() {
            self.y_meta.id
        } else {
            self.x_meta.id
        }
    }

    // TODO ignore add_liquidity during run
    pub(crate) fn add_liquidity(&mut self, x: Utxo, y: Utxo) -> Result<(), ExchangeError> {
        (x.balance.id == self.x_meta.id)
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        (y.balance.id == self.y_meta.id)
            .then(|| ())
            .ok_or(ExchangeError::InvalidPool)?;
        x.balance
            .decimal(self.x_meta.decimals)
            .ok_or(ExchangeError::InvalidNumeric)?;
        y.balance
            .decimal(self.y_meta.decimals)
            .ok_or(ExchangeError::InvalidNumeric)?;
        // TODO do other checks
        if self.k.is_zero() {
            let x_supply = x.balance.decimal(self.x_meta.decimals);
            let y_supply = y.balance.decimal(self.y_meta.decimals);
            self.k = x_supply.unwrap() * y_supply.unwrap().truncate(K_MAX_SCALE);
            self.x_utxo = Some(x);
            self.y_utxo = Some(y);
        }
        Ok(())
    }

    pub(crate) fn oppo(&self, which: &CoinId) -> Option<CoinId> {
        if *which == self.x_meta.id {
            Some(self.y_meta.id)
        } else if *which == self.y_meta.id {
            Some(self.x_meta.id)
        } else {
            None
        }
    }

    pub(crate) fn utxo<'a>(&'a self, which: &CoinId) -> Option<&'a Utxo> {
        if *which == self.x_meta.id {
            self.x_utxo.as_ref()
        } else if *which == self.y_meta.id {
            self.y_utxo.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn meta<'a>(&'a self, which: &CoinId) -> Option<&'a CoinMeta> {
        if *which == self.x_meta.id {
            Some(&self.x_meta)
        } else if *which == self.y_meta.id {
            Some(&self.y_meta)
        } else {
            None
        }
    }

    /// (x - ∆x)(y + ∆y) = xy
    /// => ∆x = x - xy / (y + ∆y)
    ///    p = ∆y / ∆x
    pub(crate) fn available_to_swap(&self, taker: &SwapQuery) -> Result<SwapOffer, ExchangeError> {
        let y = taker.balance.id;
        let x = self
            .oppo(&taker.balance.id)
            .ok_or(ExchangeError::InvalidPool)?;
        let y_utxo = self.utxo(&y).ok_or(ExchangeError::EmptyPool)?;
        let x_utxo = self.utxo(&x).ok_or(ExchangeError::EmptyPool)?;
        let y_meta = self.meta(&y).ok_or(ExchangeError::InvalidPool)?;
        let x_meta = self.meta(&x).ok_or(ExchangeError::InvalidPool)?;
        let y_supply = y_utxo
            .balance
            .decimal(y_meta.decimals)
            .ok_or(ExchangeError::InvalidPool)?;
        let x_supply = x_utxo
            .balance
            .decimal(x_meta.decimals)
            .ok_or(ExchangeError::InvalidPool)?;
        let taker_amount = taker
            .balance
            .decimal(y_meta.decimals)
            .ok_or(ExchangeError::InvalidNumeric)?;
        let offer = (x_supply - self.k / (y_supply + taker_amount)).truncate(x_meta.decimals);
        let charge = (offer * self.tx_fee_rate).truncate(x_meta.decimals);
        (offer >= x_meta.min_amount + charge && charge >= x_meta.min_amount)
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;

        let mut outputs = vec![];
        outputs.push(Output {
            balance: CoinBalance::from_decimal(x_supply + charge - offer, x_meta.decimals, x),
            pubkey: self.pubkey.clone(),
        });
        outputs.push(Output {
            balance: CoinBalance::from_decimal(y_supply + taker_amount, y_meta.decimals, y),
            pubkey: self.pubkey.clone(),
        });
        outputs.push(Output {
            balance: CoinBalance::from_decimal(offer - charge, x_meta.decimals, x),
            pubkey: taker.pubkey.clone(),
        });
        let price = (taker_amount / offer).truncate(y_meta.decimals);
        Ok(SwapOffer {
            maker_input: vec![y_utxo.clone(), x_utxo.clone()],
            outputs,
            tx_fee: charge,
            price,
        })
    }
}
