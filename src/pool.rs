use crate::{CoinBalance, CoinId, Decimal, ExchangeError, Output, Utxo};
use candid::{CandidType, Deserialize};
use serde::Serialize;

const K_MAX_SCALE: u8 = 18;

#[derive(Eq, PartialEq, CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SwapOffer {
    pub maker_input: Vec<Utxo>,
    pub outputs: Vec<Output>,
    pub tx_fee: Decimal,
    pub price: Decimal,
}

#[derive(Debug, Eq, PartialEq, Clone, CandidType, Deserialize, Serialize)]
pub struct SwapQuery {
    pub address: String,
    pub balance: CoinBalance,
}

#[derive(Clone, CandidType, Debug, Deserialize)]
pub struct CoinMeta {
    pub id: CoinId,
    pub symbol: String,
    pub min_amount: Decimal,
    pub decimals: u8,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct LiquidityPool {
    pub x_utxo: Utxo,
    pub y_utxo: Utxo,
    pub x_meta: CoinMeta,
    pub y_meta: CoinMeta,
    pub y_incomes: Decimal,
    pub x_incomes: Decimal,
    pub tx_fee_rate: Decimal,
    pub k: Decimal,
    pub address: String,
}

impl LiquidityPool {
    pub fn init(
        x_utxo: Utxo,
        y_utxo: Utxo,
        x_meta: CoinMeta,
        y_meta: CoinMeta,
        tx_fee_rate: Decimal,
        address: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(x_utxo.balance.id == x_meta.id, ExchangeError::InvalidPool);
        anyhow::ensure!(y_utxo.balance.id == y_meta.id, ExchangeError::InvalidPool);
        anyhow::ensure!(x_meta.id != y_meta.id, ExchangeError::InvalidPool);
        // TODO do extra checks
        let x_supply = x_utxo.balance.decimal(x_meta.decimals);
        let y_supply = y_utxo.balance.decimal(y_meta.decimals);
        anyhow::ensure!(x_supply.is_some(), ExchangeError::InvalidNumeric);
        anyhow::ensure!(y_supply.is_some(), ExchangeError::InvalidNumeric);
        let k = x_supply.unwrap() * y_supply.unwrap().truncate(K_MAX_SCALE);
        Ok(Self {
            x_utxo,
            y_utxo,
            x_meta,
            y_meta,
            y_incomes: Decimal::zero(),
            x_incomes: Decimal::zero(),
            tx_fee_rate,
            k,
            address,
        })
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
            Some(&self.x_utxo)
        } else if *which == self.y_meta.id {
            Some(&self.y_utxo)
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
        let y_utxo = self.utxo(&y).ok_or(ExchangeError::InvalidPool)?;
        let x_utxo = self.utxo(&x).ok_or(ExchangeError::InvalidPool)?;
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
            address: self.address.clone(),
        });
        outputs.push(Output {
            balance: CoinBalance::from_decimal(y_supply + taker_amount, y_meta.decimals, y),
            address: self.address.clone(),
        });
        outputs.push(Output {
            balance: CoinBalance::from_decimal(offer - charge, x_meta.decimals, x),
            address: taker.address.clone(),
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
