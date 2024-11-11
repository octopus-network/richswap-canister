use crate::{
    pool::{CoinMeta, LiquidityPool, SwapOffer, SwapQuery},
    CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Txid, Utxo, MIN_RESERVED_SATOSHIS,
};
use bitcoin::{
    psbt::Psbt,
    secp256k1::{Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    TapSighashType, Witness,
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
        .y_utxo
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
                .ok_or("invalid psbt: input not enough".to_string())?;
            let input = &mut psbt.inputs[i];
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&psbt.unsigned_tx.output),
                    TapSighashType::All,
                )
                .map_err(|e| e.to_string())?;
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
            input.final_script_witness = Some(Witness::p2tr_key_spend(&sig));
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

#[test]
pub fn debug_psbt() {
    let psbt_hex = "70736274ff0100fd06010200000003cd83337ead16dc2444c93b5acb9d39098fdb775fd61bbec9285a79c52619f7180000000000ffffffff69591368ad3a90e220021d38bed0d4847a6ee0129694f0944ddb3dcb39e96dd60000000000ffffffff4464fe251607338f58cf489f0c8af5b4d4fb8710bc1a7e07f34b313f80abc4600100000000ffffffff034bb3faa006000000225120be9a0f4c397015d530f77f65b419adcf7d24046af4baab6b47719ae12052c7aa80cc060200000000225120be9a0f4c397015d530f77f65b419adcf7d24046af4baab6b47719ae12052c7aab5dc34af02000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9000000000001012b00366e010000000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed0108430141069c5c173b88440ce9db6b227b773cbbd54d13506121282b4364af49a754121f03dc9eda31d6bb474fb951a068d2e0b027521555b13f453210be9070f7a5a527010001012b00902f500900000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed0001012b2202000000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90108420140ae0eadb1b10917cea04b9e3b9c624eb143f4107b615b5b0c6be71ff576c468e3a1178290ccf62e895d53cb82b74bd848f5bd1db419dd7b1f9dc2785f647da1c800000000";
    let psbt_hex = "70736274ff0100fd06010200000003cd83337ead16dc2444c93b5acb9d39098fdb775fd61bbec9285a79c52619f7180000000000ffffffff69591368ad3a90e220021d38bed0d4847a6ee0129694f0944ddb3dcb39e96dd60000000000ffffffff4464fe251607338f58cf489f0c8af5b4d4fb8710bc1a7e07f34b313f80abc4600100000000ffffffff034bb3faa006000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23b80cc060200000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23bb5dc34af02000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9000000000001012b00366e010000000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed01084301418040c5daa4a102f38c357f693222d86fec25fe0d3302246d8878e977fd314b64c5ecada807fa25327bd49d609f407ee38d452f77f1751e28aa64fa507dbafa5b010001012b00902f500900000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed0001012b2202000000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90108420140cbe05231f75174d648490cbdcdb9848065849d9b83f5254114944e8fd217266e90f56240f5723c2e901ec4f44685212eb20ed0408cd23fec051fcd18e0272b3500000000";
    let psbt_hex = "70736274ff0100fd06010200000003cd83337ead16dc2444c93b5acb9d39098fdb775fd61bbec9285a79c52619f7180000000000ffffffff69591368ad3a90e220021d38bed0d4847a6ee0129694f0944ddb3dcb39e96dd60000000000ffffffff4464fe251607338f58cf489f0c8af5b4d4fb8710bc1a7e07f34b313f80abc4600100000000ffffffff034bb3faa006000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23b80cc060200000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23bb5dc34af02000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9000000000001012b00366e010000000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed0001012b00902f500900000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed0001012b2202000000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90108420140cbe05231f75174d648490cbdcdb9848065849d9b83f5254114944e8fd217266e90f56240f5723c2e901ec4f44685212eb20ed0408cd23fec051fcd18e0272b3500000000";
    let psbt_hex = "70736274ff0100fd06010200000003cd83337ead16dc2444c93b5acb9d39098fdb775fd61bbec9285a79c52619f7180000000000ffffffff69591368ad3a90e220021d38bed0d4847a6ee0129694f0944ddb3dcb39e96dd60000000000ffffffff4464fe251607338f58cf489f0c8af5b4d4fb8710bc1a7e07f34b313f80abc4600100000000ffffffff034bb3faa006000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23b80cc060200000000225120bad9dd7f848a0e18097a512115fa6db0c0fc550271e2d918941438bb2b74e23bb5dc34af02000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9000000000001012b00366e010000000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed01084301413fea86eae1191e5349b7d5e12486434942befddcc5df98ccf239bba14f7a0d111b8fe8fca2a5372d12ad8827ee190ea6c059b0541a6e1159f0139aea501e7fc0010001012b00902f500900000022512077e91eed5b095581e0dfd14d0f6b9a9d8eb22180eba7d43c61d2ba4964b440ed01084301416307c7463cd02797532ceac344045d5a72ba1cc415eda32046e6612408d75100d7c91b4ac773dff64bb863b75b7f92e53331a4f67ba13d3b82cf0a7f8c331c92010001012b2202000000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90108420140cbe05231f75174d648490cbdcdb9848065849d9b83f5254114944e8fd217266e90f56240f5723c2e901ec4f44685212eb20ed0408cd23fec051fcd18e0272b3500000000";
    let psbt_bytes = hex::decode(&psbt_hex).unwrap();
    let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
    psbt.inputs.iter().for_each(|input| {
        println!("{:?}\n", input);
    });
    psbt.outputs.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.unsigned_tx.output.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.unsigned_tx.input.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    assert!(false);
}
