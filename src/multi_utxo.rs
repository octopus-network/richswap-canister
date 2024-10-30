use crate::{Balance, Decimal, ExchangeError, UtxoSwapRequest, Output, RuneId, Utxo};
use candid::{CandidType, Deserialize};
use std::collections::BTreeMap;

// pub type Identity = Principal;
const K_MAX_SCALE: u8 = 18;

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct UtxoSet {
    set: BTreeMap<Decimal, Vec<Utxo>>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct UtxoSwapOffer {
    pub maker_input: Vec<Utxo>,
    pub taker_input: Vec<Utxo>,
    pub outputs: Vec<Output>,
    pub fee: Balance,
    pub price: Decimal,
}

impl UtxoSet {
    pub fn from_vec(utxos: Vec<Utxo>) -> Self {
        let mut set = BTreeMap::new();
        for utxo in utxos.into_iter() {
            Self::append_to_map(&mut set, utxo);
        }
        Self { set }
    }

    pub fn sum(&self) -> Decimal {
        self.set.iter().fold(Decimal::zero(), |acc, k| {
            acc + Decimal::new(k.1.len() as i64, 0) * *k.0
        })
    }

    pub fn append(&mut self, utxo: Utxo) {
        Self::append_to_map(&mut self.set, utxo);
    }

    pub fn peek_ge(&self, at_least: Decimal) -> (Vec<Utxo>, Decimal) {
        assert!(at_least > Decimal::zero());
        let mut taken = Decimal::zero();
        let mut result = vec![];
        for (_, v) in self.set.iter() {
            let mut took = Self::peek_ge_from_page(v, at_least - taken);
            taken += took
                .iter()
                .fold(Decimal::zero(), |acc, utxo| acc + utxo.balance.value);
            result.append(&mut took);
            if taken >= at_least {
                break;
            }
        }
        (result, taken)
    }

    fn peek_ge_from_page(v: &Vec<Utxo>, at_least: Decimal) -> Vec<Utxo> {
        let mut taken = Decimal::zero();
        let mut result = vec![];
        for utxo in v.iter() {
            taken += utxo.balance.value;
            result.push(utxo.clone());
            if taken >= at_least {
                break;
            }
        }
        result
    }

    // fn take_ge_from_page(v: &mut Vec<Utxo>, at_least: Decimal) -> Vec<Utxo> {
    //     let mut taken = Decimal::zero();
    //     let mut result = vec![];
    //     while let Some(utxo) = v.pop() {
    //         taken += utxo.balance.value;
    //         result.push(utxo);
    //         if taken >= at_least {
    //             break;
    //         }
    //     }
    //     result
    // }

    fn append_to_map(map: &mut BTreeMap<Decimal, Vec<Utxo>>, utxo: Utxo) {
        if map.contains_key(&utxo.balance.value) {
            let v = map.get_mut(&utxo.balance.value).expect("");
            v.push(utxo);
        } else {
            map.insert(utxo.balance.value, vec![utxo]);
        }
    }
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct LiquidityPool {
    pub x_supply: UtxoSet,
    pub y_supply: UtxoSet,
    pub x_meta: TokenMeta,
    pub y_meta: TokenMeta,
    pub tx_fee: Decimal,
    pub k: Decimal,
}

#[derive(Clone, CandidType, Debug, Deserialize)]
pub struct TokenMeta {
    pub id: Option<RuneId>,
    pub symbol: String,
    pub min_amount: Decimal,
    pub decimals: u8,
}

impl LiquidityPool {
    pub fn new(
        x: Vec<Utxo>,
        y: Vec<Utxo>,
        x_meta: TokenMeta,
        y_meta: TokenMeta,
        fee: Decimal,
    ) -> Result<Self, ExchangeError> {
        let x_supply = UtxoSet::from_vec(x);
        let y_supply = UtxoSet::from_vec(y);
        let k = x_supply.sum() * y_supply.sum().truncate(K_MAX_SCALE);
        Ok(Self {
            x_supply,
            y_supply,
            x_meta,
            y_meta,
            tx_fee: fee,
            k,
        })
    }

    pub(crate) fn oppo(&self, which: &Option<RuneId>) -> Option<Option<RuneId>> {
        if *which == self.x_meta.id {
            Some(self.y_meta.id)
        } else if *which == self.y_meta.id {
            Some(self.x_meta.id)
        } else {
            None
        }
    }

    pub(crate) fn supply<'a>(&'a self, which: &Option<RuneId>) -> Option<&'a UtxoSet> {
        if *which == self.x_meta.id {
            Some(&self.x_supply)
        } else if *which == self.y_meta.id {
            Some(&self.y_supply)
        } else {
            None
        }
    }

    pub(crate) fn meta<'a>(&'a self, which: &Option<RuneId>) -> Option<&'a TokenMeta> {
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
    /// no matter what the param is, `x` represents the decreased token while `y` represents the increased token
    pub(crate) fn available_to_swap(
        &self,
        taker: &UtxoSwapRequest,
    ) -> Result<UtxoSwapOffer, ExchangeError> {
        (taker.amount <= taker.actual().value)
            .then(|| ())
            .ok_or(ExchangeError::InsufficientFunds)?;
        (taker.amount > Decimal::zero() && taker.amount.is_sign_positive())
            .then(|| ())
            .ok_or(ExchangeError::InvalidLiquidity)?;
        let y = taker.id;
        let x = self.oppo(&taker.id).ok_or(ExchangeError::InvalidPool)?;
        let y_supply = self.supply(&y).ok_or(ExchangeError::InvalidPool)?;
        let x_supply = self.supply(&x).ok_or(ExchangeError::InvalidPool)?;
        let y_meta = self.meta(&y).ok_or(ExchangeError::InvalidPool)?;
        let x_meta = self.meta(&x).ok_or(ExchangeError::InvalidPool)?;
        // (delta.1 > y_meta.fee)
        //     .then(|| ())
        //     .ok_or(SwapError::TooSmallFunds)?;
        let x_required =
            (x_supply.sum() - self.k / (y_supply.sum() + taker.amount)).truncate(x_meta.decimals);
        (!x_required.is_zero())
            .then(|| ())
            .ok_or(ExchangeError::TooSmallFunds)?;
        // actual >= x_required
        let (makers, actually_consumed) = x_supply.peek_ge(x_required);
        let mut outputs = vec![];
        if actually_consumed >= x_required + x_meta.min_amount {
            outputs.push(Output {
                id: x,
                address: ,
                amount: actually_consumed - x_required
            });
        }
        let price = (taker.amount / x_required).truncate(y_meta.decimals);
        Ok(UtxoSwapOffer {
            maker_input: makers,
            taker_input: taker.utxos.clone(),
            outputs,
            fee,
            price,
        })
    }

    /// if slippage_protect and partially_fill enabled:
    /// (x - ∆x)(y + ∆y) = xy
    /// ∆y / ∆x = p
    /// => ∆y = 1/2 (p x - y) + 1/2 Sqrt[p^2 x^2 - 2 p xy + y^2]
    pub(crate) fn take(
        &mut self,
        delta: Liquidity,
        allowed_slippage: Option<Decimal>,
        ref_price: Decimal,
        enable_partially_fill: bool,
    ) -> Result<(Liquidity, Liquidity, Decimal), SwapError> {
        (delta.1 > Decimal::zero())
            .then(|| ())
            .ok_or(SwapError::InvalidLiquidity)?;
        let y = delta.0;
        let x = self.oppo(&delta.0).ok_or(SwapError::InvalidPool)?;
        let x_meta = self.meta(&x).ok_or(SwapError::InvalidPool)?.clone();
        let y_supply = self.liquidity(&y).ok_or(SwapError::InvalidPool)?;
        let x_supply = self.liquidity(&x).ok_or(SwapError::InvalidPool)?;
        match allowed_slippage {
            Some(ratio) => {
                (ratio <= Decimal::one()
                    && ratio >= Decimal::zero()
                    && ref_price > Decimal::zero())
                .then(|| ())
                .ok_or(SwapError::InvalidRequirements)?;
                let (dx, p) = self.available_to_swap(&delta)?;
                let limit_p = (ref_price * ratio).truncate(p.scale() as u8);
                if p > limit_p {
                    // fill ∆x where ∆y satisfies ∆y/∆x = ref_price * ratio
                    if enable_partially_fill {
                        let p = limit_p;
                        let con_y = ((p * x_supply - y_supply)
                            + (p * p * x_supply * x_supply
                                - Decimal::new(2, 0) * p * x_supply * y_supply
                                + y_supply * y_supply)
                                .sqrt()
                                .ok_or(SwapError::InvalidLiquidity)?)
                            * Decimal::new(5, 1);
                        let (dx, _) = self.available_to_swap(&(y, con_y))?;
                        self.mutate(&x, |mut supply| supply -= dx);
                        self.mutate(&y, |mut supply| supply += con_y);
                        let charge = (dx * self.tx_fee).truncate(x_meta.decimals);
                        Ok((
                            (y, delta.1 - con_y),
                            (x, (dx - charge).truncate(x_meta.decimals)),
                            charge,
                        ))
                    } else {
                        Ok(((y, delta.1), (x, Decimal::zero()), Decimal::zero()))
                    }
                } else {
                    self.mutate(&x, |mut supply| supply -= dx);
                    self.mutate(&y, |mut supply| supply += delta.1);
                    let charge = (dx * self.tx_fee).truncate(x_meta.decimals);
                    Ok((
                        (y, Decimal::zero()),
                        (x, (dx - charge).truncate(x_meta.decimals)),
                        charge,
                    ))
                }
            }
            None => {
                let (dx, _) = self.available_to_swap(&delta)?;
                self.mutate(&x, |mut supply| supply -= dx);
                self.mutate(&y, |mut supply| supply += delta.1);
                let charge = (dx * self.tx_fee).truncate(x_meta.decimals);
                Ok((
                    (y, Decimal::zero()),
                    (x, (dx - charge).truncate(x_meta.decimals)),
                    charge,
                ))
            }
        }
    }
}
