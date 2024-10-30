use crate::{
    pool::{CoinMeta, LiquidityPool, SwapOffer, SwapQuery},
    CoinBalance, CoinId, Decimal, ExchangeError, Output, Txid, Utxo, MIN_RESERVED_SATOSHIS,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use std::str::FromStr;

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PreswapEnquiryResponse {
    inputs: Vec<Utxo>,
    outputs: Vec<Output>,
}

#[query]
pub fn preswap(args: SwapQuery) -> Result<SwapOffer, ExchangeError> {
    crate::with_pool(|p| p.available_to_swap(&args))
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SerializedUtxo {
    pub txid: String,
    pub vout: u32,
    pub balance: CoinBalance,
    pub satoshis: u64,
}

impl TryInto<Utxo> for SerializedUtxo {
    type Error = ExchangeError;

    fn try_into(self) -> Result<Utxo, Self::Error> {
        let tx_id = Txid::from_str(&self.txid).map_err(|_| ExchangeError::InvalidTxid)?;
        Ok(Utxo {
            tx_id: *tx_id.as_ref(),
            vout: self.vout,
            balance: self.balance,
            satoshis: self.satoshis,
        })
    }
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    x: SerializedUtxo,
    y: SerializedUtxo,
    addr: String,
}

#[init]
pub fn mock(args: InitArgs) {
    let InitArgs { x, y, addr } = args;
    let x_supply = x.try_into().unwrap();
    let y_supply = y.try_into().unwrap();
    let x_meta = CoinMeta {
        id: CoinId::btc(),
        decimals: 8,
        symbol: "BTC".to_string(),
        min_amount: Decimal::new(MIN_RESERVED_SATOSHIS as i64, 8),
    };
    let y_meta = CoinMeta {
        id: CoinId::rune(840001, 431),
        decimals: 2,
        symbol: "RUNE".to_string(),
        min_amount: Decimal::new(1, 2),
    };
    let pool = LiquidityPool::init(x_supply, y_supply, x_meta, y_meta, Decimal::new(1, 2), addr)
        .inspect_err(|e| ic_cdk::eprintln!("{:?}", e))
        .unwrap();
    crate::new_pool(pool);
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();
