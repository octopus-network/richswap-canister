use crate::{ExchangeError, Utxo};
use ic_canister_log::log;
use ic_log::INFO;
use ree_types::{
    bitcoin::{
        self,
        psbt::Psbt,
        sighash::{Prevouts, SighashCache},
        Address, Network, OutPoint, Script, TapSighashType, Witness,
    },
    exchange_interfaces::{CoinBalance, InputRune, OutputRune},
    CoinId, Txid,
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
        match input_rune.coin_balance {
            Some(rune) => {
                let utxo = Utxo {
                    txid: tx_in.previous_output.txid.clone().into(),
                    vout: tx_in.previous_output.vout,
                    balance: CoinBalance {
                        id: rune.id,
                        value: rune.value,
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
        match output_rune.coin_balance {
            Some(rune) => {
                let utxo = Utxo {
                    txid,
                    vout: i as u32,
                    balance: CoinBalance {
                        id: rune.id,
                        value: rune.value,
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

pub(crate) async fn sign(psbt: &mut Psbt, pool_input: &Utxo, path: Vec<u8>) -> Result<(), String> {
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let mut prevouts = vec![];
    for input in psbt.inputs.iter() {
        let pout = input
            .witness_utxo
            .as_ref()
            .cloned()
            .ok_or("witness_utxo required".to_string())?;
        prevouts.push(pout);
    }
    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;
        if let Some(_) = cmp(pool_input, outpoint) {
            (i < psbt.inputs.len())
                .then(|| ())
                .ok_or(ExchangeError::InvalidPsbt("inputs not enough".to_string()).to_string())?;
            let input = &mut psbt.inputs[i];
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .expect("couldn't construct taproot sighash");
            log!(
                INFO,
                "[latency] request schnorr sign: idx: {:?}, path: {:?}",
                i,
                path
            );
            let raw_sig = crate::sign_prehash_with_schnorr(&sighash, "key_1", path.clone())
                .await
                .map_err(|e| e.to_string())?;
            log!(
                INFO,
                "[latency] finish schnorr sign: idx: {:?}, path: {:?}",
                i,
                path
            );
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

use std::str::FromStr;

#[test]
pub fn test() {
    let hex = "70736274ff0100e30200000002f229c48485d3d3dfb9f5d4d2220b1e05a9c34b3ff3897460a1c5d45fc46ada9d0200000000fffffffff229c48485d3d3dfb9f5d4d2220b1e05a9c34b3ff3897460a1c5d45fc46ada9d0100000000ffffffff042043000000000000225120e442ca57864860f7f4e46ff3af25b11d962795ff7fbe4479dd6f060addff0cae2202000000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a7338010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a0000000000000000156a5d1200aaa3338101c3a6dd05000000fe97ab0301000000000001011f201b010000000000160014639985ae746acdfcf3d1e70973bbd42a39690d4a01086c02483045022100c2748a131dda26d071548613cfa9ac304aef4f63cf268b1916030e7dfd3ddf6c02205fc92cc5a1f4e4346bcb66d6fb73754a4823cfe21282c86afda30f04184de9ef01210294c663c9963a3083b6048a235b8a3534f58d06802e1f02de7345d029d83b421a0001012b2f6a000000000000225120e442ca57864860f7f4e46ff3af25b11d962795ff7fbe4479dd6f060addff0cae0000000000";
    let psbt_hex = hex::decode(hex).unwrap();
    let psbt = ree_types::bitcoin::Psbt::deserialize(&psbt_hex[..]).unwrap();
    let runes = vec![
        InputRune {
            tx_id: Txid::from_str(
                "9dda6ac45fd4c5a1607489f33f4bc3a9051e0b22d2d4f5b9dfd3d38584c429f2",
            )
            .unwrap(),
            vout: 2,
            btc_amount: 100_000,
            coin_balance: Some(CoinBalance {
                id: CoinId::btc(),
                value: 100_000,
            }),
        },
        InputRune {
            tx_id: Txid::from_str(
                "9dda6ac45fd4c5a1607489f33f4bc3a9051e0b22d2d4f5b9dfd3d38584c429f2",
            )
            .unwrap(),
            vout: 1,
            btc_amount: 27183,
            coin_balance: Some(CoinBalance {
                id: CoinId::rune(840106, 129),
                value: 19013441,
            }),
        },
    ];
    let pool_utxo = Utxo {
        txid: Txid::from_str("9dda6ac45fd4c5a1607489f33f4bc3a9051e0b22d2d4f5b9dfd3d38584c429f2")
            .unwrap(),
        vout: 1,
        balance: CoinBalance {
            id: CoinId::rune(840106, 129),
            value: 19013441,
        },
        satoshis: 27183,
    };
    let inputs = crate::psbt::inputs(&psbt, &runes).unwrap();
    let pool_input = inputs
        .iter()
        .find(|&i| Some(&i.0) == Some(&pool_utxo))
        .map(|i| i.0.clone())
        .ok_or("input of pool not found".to_string())
        .unwrap();

    for i in inputs {
        println!("{:?}", i);
    }
    println!("pool => {:?}", pool_input);
    assert!(false);
}
