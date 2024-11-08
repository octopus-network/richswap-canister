use crate::{
    pool::{CoinMeta, LiquidityPool, SwapOffer, SwapQuery},
    CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Txid, Utxo, MIN_RESERVED_SATOSHIS,
};
use bitcoin::{
    psbt::Psbt,
    secp256k1::{Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    TapSighashType,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::schnorr::{
    self, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument, SchnorrPublicKeyResponse,
    SignWithSchnorrArgument, SignWithSchnorrResponse,
};
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

#[derive(CandidType, Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SignPsbtCallingArgs {
    psbt_hex: String,
    tx_id: Txid,
    method: String,
    pool_id: Option<Pubkey>,
}

// TODO only called by orchestrator
// TODO function signature
#[update]
pub async fn sign_psbt(args: SignPsbtCallingArgs) -> Result<String, String> {
    let SignPsbtCallingArgs {
        psbt_hex,
        tx_id,
        method,
        pool_id,
    } = args;
    let psbt_bytes = hex::decode(&psbt_hex).map_err(|_| "invalid psbt".to_string())?;
    let mut psbt =
        Psbt::deserialize(psbt_bytes.as_slice()).map_err(|_| "invalid psbt".to_string())?;
    let pool = crate::with_pool(
        &pool_id.ok_or("pool not exisits".to_string())?,
        |p| -> Result<LiquidityPool, String> {
            let pool = p.as_ref().ok_or("invalid pool".to_string())?;
            Ok(pool.clone())
        },
    )?;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let x_utxo = pool
        .x_utxo
        .as_ref()
        .ok_or("pool not initialized".to_string())?;
    let y_utxo = pool
        .x_utxo
        .as_ref()
        .ok_or("pool not initialized".to_string())?;
    // TODO check outputs

    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;
        if outpoint.txid == x_utxo.txid.into() && outpoint.vout == x_utxo.vout
            || outpoint.txid == y_utxo.txid.into() && outpoint.vout == y_utxo.vout
        {
            (i < psbt.inputs.len())
                .then(|| ())
                .ok_or("input not enough".to_string())?;
            let mut input = &mut psbt.inputs[i];
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&psbt.unsigned_tx.output),
                    TapSighashType::All,
                )
                .map_err(|e| e.to_string())?;
            // let msg = Message::from_digest(*sighash.as_ref());
            // TODO key_id
            let signning_arg = SignWithSchnorrArgument {
                message: AsRef::<[u8; 32]>::as_ref(&sighash).to_vec(),
                derivation_path: vec![pool.base_id().to_bytes()],
                key_id: SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: "dfx_test_key".to_string(),
                },
            };
            let (schnorr_sig,): (SignWithSchnorrResponse,) =
                schnorr::sign_with_schnorr(signning_arg)
                    .await
                    .map_err(|(_, e)| e.to_string())?;
            let sig = Signature {
                signature: bitcoin::secp256k1::schnorr::Signature::from_slice(
                    &schnorr_sig.signature,
                )
                .expect("chain-key signature"),
                sighash_type: TapSighashType::All,
            };
            // TODO where does the sig should be put into?
            // input.tap_script_sigs.insert((pubkey.0, None), sig);
        }
    }
    // TODO replace the utxo
    Ok(psbt.serialize_hex())
}

fn ensure_owner() -> Result<(), String> {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        .then(|| ())
        .ok_or("Access denied".to_string())
}

ic_cdk::export_candid!();
