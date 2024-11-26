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

#[post_upgrade]
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
    (x.id != y.id)
        .then(|| ())
        .ok_or(ExchangeError::InvalidPool)?;
    (x.id == CoinId::btc() || y.id == CoinId::btc())
        .then(|| ())
        .ok_or(ExchangeError::BtcRequired)?;
    x.validate()?;
    y.validate()?;
    let base_id = if x.id == CoinId::btc() { y.id } else { x.id };
    let pool_id = crate::request_ecdsa_key("dfx_test_key".to_string(), base_id.to_bytes()).await?;
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

fn extract_pubkey(script: &Script) -> Option<Pubkey> {
    for inst in script.instructions() {
        match inst {
            Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes)) => {
                if bytes.len() == 32 {
                    return Some(
                        Pubkey::from_raw(bytes.as_bytes().to_vec())
                            .expect("x-only-pubkey must be 32 bytes"),
                    );
                }
            }
            _ => {}
        }
    }
    None
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

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let x_utxo = pool
        .x_utxo
        .as_ref()
        .ok_or("pool not initialized".to_string())?
        .clone();
    let y_utxo = pool
        .y_utxo
        .as_ref()
        .ok_or("pool not initialized".to_string())?
        .clone();
    (psbt.unsigned_tx.input.len() == input_runes.len())
        .then(|| ())
        .ok_or("invalid psbt: input not enough".to_string())?;

    (psbt.unsigned_tx.output.len() == output_runes.len())
        .then(|| ())
        .ok_or("invalid psbt: output not enough".to_string())?;
    let utxos = [x_utxo, y_utxo];
    let mut hit = 0;
    // TODO check outputs
    let mut user_rune_inputs = std::collections::HashMap::new();
    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;
        match cmp_and_clone(&utxos, outpoint) {
            // user's input
            None => {
                (i < input_runes.len())
                    .then(|| ())
                    .ok_or("invalid rune utxos: input not enough".to_string())?;
                let input_rune = &input_runes[i];
                match input_rune.rune_id {
                    Some(rune_id) => {
                        let amount = input_rune.rune_amount.ok_or("rune amount required")?;
                        user_rune_inputs
                            .entry(rune_id)
                            .and_modify(|t| *t += amount)
                            .or_insert(amount);
                    }
                    None => {
                        user_rune_inputs
                            .entry(CoinId::btc())
                            .and_modify(|t| *t += input_rune.btc_amount)
                            .or_insert(input_rune.btc_amount);
                    }
                }
            }
            // pool's input
            Some(_utxo) => hit += 1,
        }
    }
    if hit != 2 {
        return Err("Pool's UTXOs have been spent".to_string());
    }

    // let mut user_rune_outputs = std::collections::HashMap::new();
    let (mut new_x, mut new_y) = (None::<Utxo>, None::<Utxo>);
    let mut user_pubkey = Option::<Pubkey>::None;
    for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            continue;
        }
        if output.script_pubkey.is_p2tr() {
            // match extract_pubkey(&output.script_pubkey) {
            //     Some(pubkey) if pubkey == pool_id => {
            //         let output_rune = &output_runes[i];
            //         match output_rune.rune_id {
            //             Some(rune_id) => {
            //                 let amount = output_rune.rune_amount.ok_or("rune amount required")?;
            //                 new_x.replace(Utxo {
            //                     txid: tx_id,
            //                     vout: i as u32,
            //                     balance: CoinBalance {
            //                         id: rune_id,
            //                         value: amount,
            //                     },
            //                     satoshis: output_rune
            //                         .btc_amount
            //                         .try_into()
            //                         .expect("satoshis amount overflow"),
            //                 });
            //             }
            //             None => {
            //                 new_y.replace(Utxo {
            //                     txid: tx_id,
            //                     vout: i as u32,
            //                     balance: CoinBalance {
            //                         id: CoinId::btc(),
            //                         value: output_rune.btc_amount,
            //                     },
            //                     satoshis: output_rune
            //                         .btc_amount
            //                         .try_into()
            //                         .expect("satoshis amount overflow"),
            //                 });
            //             }
            //         }
            //     }
            //     Some(pubkey) => {
            //         user_pubkey.replace(pubkey);
            //         let output_rune = &output_runes[i];
            //         match output_rune.rune_id {
            //             Some(rune_id) => {
            //                 let amount = output_rune.rune_amount.ok_or("rune amount required")?;
            //                 user_rune_outputs
            //                     .entry(rune_id)
            //                     .and_modify(|t| *t += amount)
            //                     .or_insert(amount);
            //             }
            //             None => {
            //                 user_rune_outputs
            //                     .entry(CoinId::btc())
            //                     .and_modify(|t| *t += output_rune.btc_amount)
            //                     .or_insert(output_rune.btc_amount);
            //             }
            //         }
            //     }
            //     None => {}
            // }
        }
    }

    (new_x.is_some() && new_y.is_some())
        .then(|| ())
        .ok_or("invalid psbt: outputs associated with pool not correct".to_string())?;

    (user_rune_inputs.len() <= 2 && !user_rune_inputs.is_empty())
        .then(|| ())
        .ok_or("invalid rune utxos: user's input should contain only 1 rune assets".to_string())?;

    if user_rune_inputs.len() == 1 {
        // btc -> rune
        // let total_input = user_rune_inputs.get(&CoinId::btc()).expect("");
        // let total_output = user_rune_outputs.get(&CoinId::btc()).expect("");
        // let user_paid =
        //     total_input - (total_input - total_output) - new_y.as_ref().expect("").balance.value;
        // let assert_outputs = pool
        //     .available_to_swap(&SwapQuery {
        //         pubkey: user_pubkey.expect("user pubkey not found"),
        //         balance: CoinBalance {
        //             id: CoinId::btc(),
        //             value: user_paid,
        //         },
        //     })
        //     .map_err(|e| e.to_string())?;
    } else {
        // rune -> btc
    }

    // TODO move this to an independent function
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
                "dfx_test_key".to_string(),
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
        // pool.x_utxo.replace(new_x.expect("qed;"));
        // pool.y_utxo.replace(new_y.expect("qed;"));
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
