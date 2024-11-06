use crate::{
    pool::{CoinMeta, LiquidityPool, SwapOffer, SwapQuery},
    CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Txid, Utxo, MIN_RESERVED_SATOSHIS,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PreswapEnquiryResponse {
    inputs: Vec<Utxo>,
    outputs: Vec<Output>,
}

#[query]
pub fn pre_swap(id: Pubkey, args: SwapQuery) -> Result<SwapOffer, ExchangeError> {
    crate::with_pool(&id, |p| {
        p.as_ref()
            .ok_or(ExchangeError::InvalidPool)?
            .available_to_swap(&args)
    })
}

#[update]
pub async fn create(x: CoinMeta, y: CoinMeta) -> Result<Pubkey, ExchangeError> {
    (x.id != y.id)
        .then(|| ())
        .ok_or(ExchangeError::InvalidPool)?;
    (x.id == CoinId::btc() || y.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::BtcRequired)?;
    x.validate()?;
    y.validate()?;
    crate::create_pool(x, y).await
}

// TODO this is for mocking initialization
#[update]
pub async fn mock_add_liquidity(x: Utxo, y: Utxo, pubkey: Pubkey) -> Result<(), ExchangeError> {
    crate::with_pool_mut(&pubkey, |p| {
        let mut pool = p.ok_or(ExchangeError::InvalidPool)?;
        pool.add_liquidity(x.clone(), y.clone())?;
        Ok(Some(pool))
    })?;
    Ok(())
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();
