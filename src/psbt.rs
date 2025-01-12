use crate::{
    canister::{InputRune, OutputRune},
    pool::LiquidityPool,
    CoinBalance, CoinId, ExchangeError, Txid, Utxo,
};
use bitcoin::{
    psbt::Psbt,
    sighash::{Prevouts, SighashCache},
    Address, Network, OutPoint, Script, TapSighashType, Witness,
};

pub(crate) fn extract_addr(script: &Script) -> Option<String> {
    Address::from_script(script, Network::Bitcoin)
        .map(|addr| addr.to_string())
        .ok()
}

pub(crate) fn inputs(
    psbt: &Psbt,
    input_runes: &[InputRune],
) -> Result<Vec<(Utxo, String)>, ExchangeError> {
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
        let addr = extract_addr(&witness.script_pubkey).ok_or(ExchangeError::InvalidPsbt(
            format!("uncognized input {}", i),
        ))?;
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
                r.push((utxo, addr));
            }
            None => {
                let utxo = Utxo {
                    txid: tx_in.previous_output.txid.clone().into(),
                    vout: tx_in.previous_output.vout,
                    balance: CoinBalance {
                        id: CoinId::btc(),
                        value: input_rune.btc_amount as u128,
                    },
                    satoshis: input_rune
                        .btc_amount
                        .try_into()
                        .expect("satoshis amount overflow"),
                };
                r.push((utxo, addr));
            }
        }
    }
    Ok(r)
}

pub(crate) fn outputs(
    txid: Txid,
    psbt: &Psbt,
    output_runes: &[OutputRune],
) -> Result<Vec<(Utxo, String)>, ExchangeError> {
    (psbt.unsigned_tx.output.len() == output_runes.len()
        && psbt.outputs.len() == output_runes.len())
    .then(|| ())
    .ok_or(ExchangeError::InvalidPsbt("outputs not enough".to_string()))?;
    let mut r = vec![];
    for (i, tx_out) in psbt.unsigned_tx.output.iter().enumerate() {
        let addr = extract_addr(&tx_out.script_pubkey);
        if addr.is_none() {
            continue;
        }
        (i < output_runes.len() && i < psbt.outputs.len())
            .then(|| ())
            .ok_or(ExchangeError::InvalidPsbt("outputs not enough".to_string()))?;
        let output_rune = &output_runes[i];
        match output_rune.rune_id {
            Some(rune_id) => {
                let amount = output_rune
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
                r.push((utxo, addr.unwrap()));
            }
            None => {
                let utxo = Utxo {
                    txid,
                    vout: i as u32,
                    balance: CoinBalance {
                        id: CoinId::btc(),
                        value: output_rune.btc_amount as u128,
                    },
                    satoshis: output_rune
                        .btc_amount
                        .try_into()
                        .expect("satoshis amount overflow"),
                };
                r.push((utxo, addr.unwrap()));
            }
        }
    }
    Ok(r)
}

fn cmp<'a>(mine: &'a Utxo, outpoint: &OutPoint) -> Option<&'a Utxo> {
    (Into::<bitcoin::Txid>::into(mine.txid) == outpoint.txid && mine.vout == outpoint.vout)
        .then(|| mine)
}

pub(crate) async fn sign(psbt: &mut Psbt, pool: &LiquidityPool) -> Result<(), String> {
    let state = pool
        .states
        .last()
        .ok_or(ExchangeError::EmptyPool.to_string())?;
    let utxo = state
        .utxo
        .as_ref()
        .ok_or(ExchangeError::EmptyPool.to_string())?;
    let path = pool.base_id().to_bytes();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let prevouts = Prevouts::All(&psbt.unsigned_tx.output);
    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;
        if let Some(_) = cmp(utxo, outpoint) {
            (i < psbt.inputs.len())
                .then(|| ())
                .ok_or(ExchangeError::InvalidPsbt("inputs not enough".to_string()).to_string())?;
            let input = &mut psbt.inputs[i];
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &prevouts, TapSighashType::Default)
                .expect("couldn't construct taproot sighash");
            let raw_sig = crate::sign_prehash_with_schnorr(&sighash, "key_1", path.clone())
                .await
                .map_err(|e| e.to_string())?;
            let inner_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&raw_sig)
                .expect("assert: chain-key schnorr signature is 64-bytes format");
            let signature = bitcoin::taproot::Signature {
                signature: inner_sig,
                sighash_type: TapSighashType::Default,
            };
            input.final_script_witness = Some(Witness::p2tr_key_spend(&signature));
        }
    }
    Ok(())
}

// #[test]
// pub fn test_reorg_outputs() {
//     use std::str::FromStr;
//     let psbt_hex = "70736274ff0100fd170102000000038d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630300000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630400000000ffffffff8d78348803a5c96d9aecb795aad58650c86ba1e039e6918d6aaf5fcf6a2cca630200000000ffffffff0500000000000000000d6a5d0a00c0a233ce06acfa72022202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db052202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a5700010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a443a000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000001011fe94b010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086b02473044022100ef9ce94acdf2cc79434aa5b610b682f2eb057010802bc24d66587a45e0b2861f021f43b5ac2c8bc2a44da78ae42e3887b155b414a7f0ce116cd9f6094c92fab5b401210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001011f3413000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db050001011f2202000000000000160014fdc6db9c64ac369e0453531db338ce7301c6db05000000000000";
//     let psbt_bytes = hex::decode(&psbt_hex).unwrap();
//     let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();
//     let txid =
//         crate::Txid::from_str("a846f3f3b4d0b642331b46c9924048b74891452384bd2af72714b83e3d9bbf0b")
//             .unwrap();
//     let runes = vec![
//         OutputRune {
//             btc_amount: 0,
//             rune_id: None,
//             rune_amount: None,
//         },
//         OutputRune {
//             btc_amount: 546,
//             rune_id: Some(CoinId::rune(840000, 846)),
//             rune_amount: Some(100000),
//         },
//         OutputRune {
//             btc_amount: 546,
//             rune_id: Some(CoinId::rune(840000, 846)),
//             rune_amount: Some(100000),
//         },
//         OutputRune {
//             btc_amount: 65623,
//             rune_id: None,
//             rune_amount: None,
//         },
//         OutputRune {
//             btc_amount: 14916,
//             rune_id: None,
//             rune_amount: None,
//         },
//     ];
//     let outputs = outputs(txid, &psbt, &runes).unwrap();
//     outputs.iter().for_each(|(o, p)| {
//         println!("{:?} {:?}", o, p);
//     });
//     let pool_pubkey = PubkeyHash::from_str("fdc6db9c64ac369e0453531db338ce7301c6db05").unwrap();
//     let rune_output = outputs
//         .iter()
//         .find(|&o| o.1 == pool_pubkey && o.0.balance.id != CoinId::btc())
//         .map(|o| o.0.clone());
//     assert!(rune_output.is_some());
//     let b = &outputs[3];
//     assert_eq!(b.0.balance.id, CoinId::btc());
//     assert_eq!(b.1, pool_pubkey);
//     let btc_output = outputs
//         .iter()
//         .find(|&o| o.1 == pool_pubkey && o.0.balance.id == CoinId::btc())
//         .map(|o| o.0.clone());
//     assert!(btc_output.is_some());
// }
