use crate::{
    canister::{InputRune, OutputRune},
    pool::LiquidityPool,
    CoinBalance, CoinId, ExchangeError, Txid, Utxo,
};
use bitcoin::{
    hashes::Hash,
    psbt::Psbt,
    sighash::{EcdsaSighashType, Prevouts, SighashCache},
    Amount, OutPoint, PubkeyHash, Script, TapSighashType, TxOut, Witness,
};

pub(crate) fn extract_pubkey_hash(script: &Script) -> Option<PubkeyHash> {
    for inst in script.instructions() {
        match inst {
            Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes)) => {
                if bytes.len() == 20 {
                    return Some(
                        bitcoin::PubkeyHash::from_slice(bytes.as_bytes())
                            .expect("pubkey hash is 20 bytes"),
                    );
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn inputs(
    psbt: &Psbt,
    input_runes: &[InputRune],
) -> Result<Vec<(Utxo, PubkeyHash)>, ExchangeError> {
    (psbt.unsigned_tx.input.len() == input_runes.len() && psbt.inputs.len() == input_runes.len())
        .then(|| ())
        .ok_or(ExchangeError::InvalidPsbt("inputs not enough".to_string()))?;
    let mut r = vec![];
    for (i, tx_in) in psbt.unsigned_tx.input.iter().enumerate() {
        (i < input_runes.len() && i < psbt.inputs.len())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPsbt("inputs not enough".to_string()))?;
        let input_rune = &input_runes[i];
        let input = &psbt.inputs[i];
        let witness = input
            .witness_utxo
            .as_ref()
            .ok_or(ExchangeError::InvalidPsbt(
                "witness_utxo required".to_string(),
            ))?;
        let pubkey_hash = extract_pubkey_hash(&witness.script_pubkey).ok_or(
            ExchangeError::InvalidPsbt(format!("unsupported input type: {}", i)),
        )?;
        match input_rune.rune_id {
            Some(rune_id) => {
                let amount = input_rune
                    .rune_amount
                    .ok_or(ExchangeError::InvalidPsbt(format!(
                        "rune amount is required for input {}",
                        i
                    )))?;
                let utxo = Utxo {
                    txid: tx_in.previous_output.txid.clone().into(),
                    vout: tx_in.previous_output.vout,
                    balance: CoinBalance {
                        id: rune_id,
                        value: amount,
                    },
                    satoshis: input_rune
                        .btc_amount
                        .try_into()
                        .expect("satoshis amount overflow"),
                };
                r.push((utxo, pubkey_hash));
            }
            None => {
                let utxo = Utxo {
                    txid: tx_in.previous_output.txid.clone().into(),
                    vout: tx_in.previous_output.vout,
                    balance: CoinBalance {
                        id: CoinId::btc(),
                        value: input_rune.btc_amount,
                    },
                    satoshis: input_rune
                        .btc_amount
                        .try_into()
                        .expect("satoshis amount overflow"),
                };
                r.push((utxo, pubkey_hash));
            }
        }
    }
    Ok(r)
}

pub(crate) fn outputs(
    txid: Txid,
    psbt: &Psbt,
    output_runes: &[OutputRune],
) -> Result<Vec<(Utxo, PubkeyHash)>, ExchangeError> {
    (psbt.unsigned_tx.output.len() == output_runes.len()
        && psbt.outputs.len() == output_runes.len())
    .then(|| ())
    .ok_or(ExchangeError::InvalidPsbt("outputs not enough".to_string()))?;
    let mut r = vec![];
    for (i, tx_out) in psbt.unsigned_tx.output.iter().enumerate() {
        if tx_out.script_pubkey.is_op_return() {
            continue;
        }
        if tx_out.script_pubkey.is_p2tr() {
            continue;
        }
        if tx_out.script_pubkey.is_p2wpkh() {
            let pubkey_hash = extract_pubkey_hash(&tx_out.script_pubkey);
            if pubkey_hash.is_none() {
                continue;
            }
            (i < output_runes.len() && i < psbt.outputs.len())
                .then(|| ())
                .ok_or(ExchangeError::InvalidPsbt("outputs not enough".to_string()))?;
            let output_rune = &output_runes[i];
            match output_rune.rune_id {
                Some(rune_id) => {
                    let amount =
                        output_rune
                            .rune_amount
                            .ok_or(ExchangeError::InvalidPsbt(format!(
                                "rune amount is required for output {}",
                                i
                            )))?;
                    let utxo = Utxo {
                        txid,
                        vout: i as u32,
                        balance: CoinBalance {
                            id: rune_id,
                            value: amount,
                        },
                        satoshis: output_rune
                            .btc_amount
                            .try_into()
                            .expect("satoshis amount overflow"),
                    };
                    r.push((utxo, pubkey_hash.unwrap()));
                }
                None => {
                    let utxo = Utxo {
                        txid,
                        vout: i as u32,
                        balance: CoinBalance {
                            id: CoinId::btc(),
                            value: output_rune.btc_amount,
                        },
                        satoshis: output_rune
                            .btc_amount
                            .try_into()
                            .expect("satoshis amount overflow"),
                    };
                    r.push((utxo, pubkey_hash.unwrap()));
                }
            }
        }
    }
    Ok(r)
}

fn cmp_and_clone(mine: &[Utxo], outpoint: &OutPoint) -> Option<Utxo> {
    for utxo in mine.iter() {
        if Into::<bitcoin::Txid>::into(utxo.txid) == outpoint.txid && utxo.vout == outpoint.vout {
            return Some(utxo.clone());
        }
    }
    None
}

pub(crate) async fn sign(psbt: &mut Psbt, pool: &LiquidityPool) -> Result<(), String> {
    let utxos = [pool.btc_utxo.clone(), pool.rune_utxo.clone()];
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
    Ok(())
}

#[test]
pub fn test_extract_pubkey() {
    use std::str::FromStr;
    let psbt_hex = "70736274ff0100fd170102000000038d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630300000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630400000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630200000000ffffffff0500000000000000000d6a5d0a00c0a233ce06acfa72022202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db052202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a5700010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a443a000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000001011fe94b010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086b02473044022100ef9ce94acdf2cc79434aa5b610b682f2eb057010802bc24d66587a45e0b2861f021f43b5ac2c8bc2a44da78ae42e3887b155b414a7f0ce116cd9f6094c92fab5b401210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001011f3413000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db050001011f2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000000";
    let psbt_bytes = hex::decode(&psbt_hex).unwrap();
    let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
    for (i, input) in psbt.inputs.iter().enumerate() {
        let pubkey_hash = extract_pubkey_hash(&input.witness_utxo.as_ref().unwrap().script_pubkey);
        if i == 0 {
            let assert = PubkeyHash::from_str("639985ae746acdfcf3d1e70973bbd42a39690d4a").unwrap();
            assert_eq!(Some(assert), pubkey_hash);
        } else {
            let assert = PubkeyHash::from_str("fdc6db9c64ac369e0453531db338ce7301c6db05").unwrap();
            assert_eq!(Some(assert), pubkey_hash);
        }
    }
    // for (i, tx_out) in psbt.unsigned_tx.output.iter().enumerate() {
    // let pubkey_hash = extract_pubkey_hash(&output.script_pubkey);
    // if i == 0 {
    //     let assert = PubkeyHash::from_str("639985ae746acdfcf3d1e70973bbd42a39690d4a").unwrap();
    //     assert_eq!(Some(assert), pubkey_hash);
    // } else {
    //     let assert = PubkeyHash::from_str("fdc6db9c64ac369e0453531db338ce7301c6db05").unwrap();
    //     assert_eq!(Some(assert), pubkey_hash);
    // }
    //     println!("{:?}", tx_out);
    // }
    // assert!(false);
}

#[test]
pub fn test_reorg_outputs() {
    use std::str::FromStr;
    let psbt_hex = "70736274ff0100fd170102000000038d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630300000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630400000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630200000000ffffffff0500000000000000000d6a5d0a00c0a233ce06acfa72022202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db052202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a5700010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a443a000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000001011fe94b010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086b02473044022100ef9ce94acdf2cc79434aa5b610b682f2eb057010802bc24d66587a45e0b2861f021f43b5ac2c8bc2a44da78ae42e3887b155b414a7f0ce116cd9f6094c92fab5b401210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001011f3413000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db050001011f2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000000";
    let psbt_bytes = hex::decode(&psbt_hex).unwrap();
    let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
    let txid =
        crate::Txid::from_str("a846f3f3b4d0b642331b46c9924048b74891452384bd2af72714b83e3d9bbf0b")
            .unwrap();
    let runes = vec![
        OutputRune {
            btc_amount: 0,
            rune_id: None,
            rune_amount: None,
        },
        OutputRune {
            btc_amount: 546,
            rune_id: Some(CoinId::rune(840000, 846)),
            rune_amount: Some(100000),
        },
        OutputRune {
            btc_amount: 546,
            rune_id: Some(CoinId::rune(840000, 846)),
            rune_amount: Some(100000),
        },
        OutputRune {
            btc_amount: 65623,
            rune_id: None,
            rune_amount: None,
        },
        OutputRune {
            btc_amount: 14916,
            rune_id: None,
            rune_amount: None,
        },
    ];
    let outputs = outputs(txid, &psbt, &runes).unwrap();
    outputs.iter().for_each(|(o, p)| {
        println!("{:?} {:?}", o, p);
    });
    let pool_pubkey = PubkeyHash::from_str("fdc6db9c64ac369e0453531db338ce7301c6db05").unwrap();
    let rune_output = outputs
        .iter()
        .find(|&o| o.1 == pool_pubkey && o.0.balance.id != CoinId::btc())
        .map(|o| o.0.clone());
    assert!(rune_output.is_some());
    let b = &outputs[3];
    assert_eq!(b.0.balance.id, CoinId::btc());
    assert_eq!(b.1, pool_pubkey);
    let btc_output = outputs
        .iter()
        .find(|&o| o.1 == pool_pubkey && o.0.balance.id == CoinId::btc())
        .map(|o| o.0.clone());
    assert!(btc_output.is_some());
}
