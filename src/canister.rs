use crate::{
    pool::{CoinMeta, LiquidityPool, SwapOffer, SwapQuery},
    CoinBalance, CoinId, Decimal, ExchangeError, Output, Pubkey, Txid, Utxo, MIN_RESERVED_SATOSHIS,
};
use bitcoin::{
    psbt::Psbt,
    sighash::{EcdsaSighashType, Prevouts, SighashCache},
    Amount, OutPoint, Script, TapSighashType, TxOut, Witness,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use serde::Serialize;

#[pre_upgrade]
pub fn init() {
    crate::reset_all_pools();
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
    // TODO
    crate::reset_all_pools();
    (x.id != y.id)
        .then(|| ())
        .ok_or(ExchangeError::InvalidPool)?;
    (x.id == CoinId::btc() || y.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::BtcRequired)?;
    x.validate()?;
    y.validate()?;
    let base_id = if x.id == CoinId::btc() { y.id } else { x.id };
    // let pool_id = crate::request_ecdsa_key("dfx_test_key".to_string(), base_id.to_bytes()).await?;
    let pool_id = crate::request_ecdsa_key("key_1".to_string(), base_id.to_bytes()).await?;
    crate::create_pool(x, y, pool_id.clone()).await?;
    Ok(pool_id)
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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InputRune {
    pub tx_id: String,
    pub vout: u32,
    pub btc_amount: u128,
    pub rune_id: Option<CoinId>,
    pub rune_amount: Option<u128>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OutputRune {
    pub btc_amount: u128,
    pub rune_id: Option<CoinId>,
    pub rune_amount: Option<u128>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignPsbtCallingArgs {
    pub nonce: u64,
    pub psbt_hex: String,
    pub tx_id: Txid,
    pub method: String,
    pub pool_id: Option<Pubkey>,
    pub input_runes: Vec<InputRune>,
    pub output_runes: Vec<OutputRune>,
}

fn cmp_and_clone(mine: &[Utxo], outpoint: &OutPoint) -> Option<Utxo> {
    for utxo in mine.iter() {
        if Into::<bitcoin::Txid>::into(utxo.txid) == outpoint.txid && utxo.vout == outpoint.vout {
            return Some(utxo.clone());
        }
    }
    None
}

// TODO only called by orchestrator
// TODO function signature
#[update]
pub async fn sign_psbt(args: SignPsbtCallingArgs) -> Result<String, String> {
    let SignPsbtCallingArgs {
        nonce,
        psbt_hex,
        tx_id,
        method,
        pool_id,
        input_runes,
        output_runes,
    } = args;
    let psbt_bytes = hex::decode(&psbt_hex).map_err(|_| "invalid psbt".to_string())?;
    let mut psbt =
        Psbt::deserialize(psbt_bytes.as_slice()).map_err(|_| "invalid psbt".to_string())?;
    let pool_id = pool_id.ok_or("pool not exisits".to_string())?;
    let pool = crate::with_pool(&pool_id, |p| -> Result<LiquidityPool, String> {
        let pool = p.as_ref().ok_or("invalid pool".to_string())?;
        Ok(pool.clone())
    })?;
    if pool.nonce != nonce {
        return Err("state expired".to_string());
    }

    let (btc_utxo, rune_utxo) = if pool
        .x_utxo
        .as_ref()
        .ok_or("pool not initialized".to_string())?
        .balance
        .id
        == CoinId::btc()
    {
        (
            pool.x_utxo
                .as_ref()
                .ok_or("pool not initialized".to_string())?
                .clone(),
            pool.y_utxo
                .as_ref()
                .ok_or("pool not initialized".to_string())?
                .clone(),
        )
    } else {
        (
            pool.y_utxo
                .as_ref()
                .ok_or("pool not initialized".to_string())?
                .clone(),
            pool.x_utxo
                .as_ref()
                .ok_or("pool not initialized".to_string())?
                .clone(),
        )
    };
    let inputs = crate::psbt::inputs(&psbt, &input_runes).map_err(|e| e.to_string())?;
    let outputs = crate::psbt::outputs(tx_id, &psbt, &output_runes).map_err(|e| e.to_string())?;
    let any_pubkey_of_user = inputs
        .iter()
        .find(|i| i.1 != pool.pubkey)
        .map(|i| i.1.clone())
        .ok_or("no user pubkey found".to_string())?;
    let total_user_satoshis_input = inputs
        .iter()
        .filter(|&i| i.1 != pool.pubkey)
        .filter(|&i| i.0.balance.id == CoinId::btc())
        .map(|i| i.0.balance)
        .reduce(|a, b| CoinBalance {
            id: CoinId::btc(),
            value: a.value + b.value,
        });
    let total_user_rune_input = inputs
        .iter()
        .filter(|&i| i.1 != pool.pubkey)
        .filter(|&i| i.0.balance.id != CoinId::btc())
        .map(|i| i.0.balance)
        .reduce(|a, b| {
            assert!(a.id == b.id);
            CoinBalance {
                id: b.id,
                value: a.value + b.value,
            }
        });
    let btc_output = outputs
        .iter()
        .find(|&o| o.1 == pool.pubkey)
        .filter(|&o| o.0.balance.id == CoinId::btc())
        .map(|o| o.0.clone())
        .ok_or("no btc output of pool".to_string())?;
    let rune_output = outputs
        .iter()
        .find(|&o| o.1 == pool.pubkey)
        .filter(|&o| o.0.balance.id != CoinId::btc())
        .map(|o| o.0.clone())
        .ok_or("no rune output of pool".to_string())?;

    if let Some(user_rune_input) = total_user_rune_input {
        // this indicates rune => btc
        let total_user_rune_output = outputs
            .iter()
            .filter(|&o| o.1 != pool.pubkey)
            .filter(|&o| o.0.balance.id != CoinId::btc())
            .map(|o| o.0.balance)
            .reduce(|a, b| {
                assert!(a.id == b.id);
                CoinBalance {
                    id: b.id,
                    value: a.value + b.value,
                }
            });
        let total_offer = if let Some(user_rune_output) = total_user_rune_output {
            assert!(user_rune_input.id == user_rune_output.id);
            assert!(user_rune_input.value > user_rune_output.value);
            CoinBalance {
                id: user_rune_output.id,
                value: user_rune_input.value - user_rune_output.value,
            }
        } else {
            CoinBalance {
                id: user_rune_input.id,
                value: user_rune_input.value,
            }
        };
        // let assert_outputs = pool
        //     .available_to_swap(&SwapQuery {
        //         pubkey: any_pubkey_of_user,
        //         balance: total_offer,
        //     })
        //     .map_err(|e| e.to_string())?;
    } else {
        // this indicates btc => rune

        (rune_utxo.balance.value > rune_output.balance.value)
            .then(|| ())
            .ok_or("invalid swap request".to_string())?;
        // let assert_outputs = pool
        //     .available_to_swap(&SwapQuery {
        //         pubkey: any_pubkey_of_user,
        //         balance: CoinBalance {
        //             id: rune_output.balance.id,
        //             value: rune_utxo.balance.value - rune_output.balance.value,
        //         },
        //     })
        //     .map_err(|e| e.to_string())?;
    }

    let utxos = [btc_utxo.clone(), rune_utxo.clone()];
    // TODO move this to an independent function
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;
        if let Some(utxo) = cmp_and_clone(&utxos, outpoint) {
            (i < psbt.inputs.len())
                .then(|| ())
                .ok_or("invalid psbt: inputs not enough".to_string())?;
            let input = &mut psbt.inputs[i];
            // FIXME can we assume that UTXOs of pool are P2WPKH?
            let unlock_script = input
                .witness_utxo
                .as_ref()
                .ok_or("the pool utxo is not P2WPKH?".to_string())?
                .script_pubkey
                .clone();
            let sighash = cache
                .p2wpkh_signature_hash(
                    i,
                    &unlock_script,
                    Amount::from_sat(utxo.satoshis),
                    EcdsaSighashType::All,
                )
                .map_err(|e| e.to_string())?;
            // TODO key_id
            let raw_signature = crate::sign_prehash_with_ecdsa(
                &sighash,
                // "dfx_test_key".to_string(),
                "key_1".to_string(),
                pool.base_id().to_bytes(),
            )
            .await
            .map_err(|e| e.to_string())?;
            let signature = bitcoin::ecdsa::Signature {
                signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&raw_signature)
                    .expect("assert: chain-key signature is 64-bytes compact format"),
                sighash_type: EcdsaSighashType::All,
            };
            input.final_script_witness = Some(Witness::p2wpkh(
                &signature,
                &bitcoin::secp256k1::PublicKey::from_slice(&pool.pubkey.0.to_bytes())
                    .expect("assert: pool pubkey is generated by ICP"),
            ));
        }
    }
    crate::with_pool_mut(&pool_id, |p| {
        let mut pool = p.expect("pool not initialized");
        pool.x_utxo.replace(btc_output);
        pool.y_utxo.replace(rune_output);
        pool.nonce += 1;
        Ok(Some(pool))
    });

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
    use std::str::FromStr;
    let psbt_hex = "70736274ff0100fd47010200000003a160c837f02001986a6948b943af3361eaf976e94f509f03b30641ad3ecf4da40000000000ffffffff88a188d28ca3529116adebfabb53ae5d122a3319f0c97b848423aaa3d91cbcd80200000000ffffffff813eef858acb1726d52fee6fe319a62ca5d7ea078514f8bea4d974d5c5a8150a0000000000ffffffff0500000000000000000d6a5d0a00c0a233ce0695dd57022202000000000000225120b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe762202000000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90ccd020000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce9983a000000000000225120b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76000000000001012b8813000000000000225120b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76011720b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe760001012b2202000000000000225120b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76011720b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe760001012b400d030000000000225120269c1807a44070812e07865efc712c189fdc2624b7cd8f20d158e4f71ba83ce90108420140a7e635eb04f2c7d16b170e202356126f621368295e42becc32fbdd5214f704dfffa331e14d829a5b7261faa04b55f3379f0dac5ff00a80ccdc4e18364fb9ebdd000000000000";
    let psbt_hex = "70736274ff0100fd1801020000000349be4ee3213f275e720244eb30c6be478e4858b53ea5e554783226d7d0016def0100000000ffffffffa6000363e84f15b0551094e60454206aa6cdbabe982a065030201b1b187a19520000000000ffffffff7fbe48d7e08c8c74f37dbc3bf9e8e8518f98529dd75f3432bde7a00b9e00f5cd0200000000ffffffff0500000000000000000e6a5d0b00c0a233ce0695b58e01022202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db053119000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a289a010000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000001011ff5b8010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086c02483045022100a8eeaf6364f986bda4d5cd2a913d7abceb5e6041b96c077ac01ed8f68d2e81b702204d098d548f07e94c01a19245e6cf69753cdf9d879563827bc4052c1401dff49a01210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001011f8813000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db050001011f2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000000";
    let psbt_bytes = hex::decode(&psbt_hex).unwrap();
    let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
    psbt.inputs.iter().for_each(|input| {
        println!("{:?}\n", input);
    });
    psbt.unsigned_tx.input.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.outputs.iter().for_each(|output| {
        println!("{:?}\n", output);
    });
    psbt.unsigned_tx.output.iter().for_each(|output| {
        println!("{:?}\n", output);
    });

    let pool_id =
        Pubkey::from_str("03b8dbea6d19d68fdcb70b248db7caeb4f3fcac95673f8877f5d1dcff459adfe76")
            .unwrap();
    let (mut new_x, mut new_y) = (None::<Utxo>, None::<Utxo>);
    let mut user_pubkey = Option::<Pubkey>::None;
    let output_runes = vec![
        None,
        Some(CoinId::rune(840001, 431)),
        Some(CoinId::rune(840001, 431)),
        None,
        None,
    ];
    for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            continue;
        }
        if output.script_pubkey.is_p2tr() {
            match extract_pubkey(&output.script_pubkey) {
                Some(pubkey) if pubkey == pool_id => {
                    let output_rune = &output_runes[i];
                    match output_rune {
                        Some(rune_id) => {
                            new_x.replace(Utxo {
                                txid: Txid::from_str("0a15a8c5d574d9a4bef8148507ead7a52ca619e36fee2fd52617cb8a85ef3e81").unwrap(),
                                vout: i as u32,
                                balance: CoinBalance {
                                    id: *rune_id,
                                    value: 0,
                                },
                                satoshis: 0,
                            });
                        }
                        None => {
                            new_y.replace(Utxo {
                                txid: Txid::from_str("0a15a8c5d574d9a4bef8148507ead7a52ca619e36fee2fd52617cb8a85ef3e81").unwrap(),
                                vout: i as u32,
                                balance: CoinBalance {
                                    id: CoinId::btc(),
                                    value: 0,
                                },
                                satoshis: 0,
                            });
                        }
                    }
                    // TODO replace the utxo
                }
                Some(pubkey) => {
                    user_pubkey.replace(pubkey);
                    let output_rune = &output_runes[i];
                    match output_rune {
                        Some(rune_id) => {}
                        None => {}
                    }
                }
                None => {}
            }
        }
    }
    assert!(new_x.is_some());
    assert!(new_y.is_some());
    println!("{:?}", new_x);
    println!("{:?}", new_y);
    assert!(false);
}
