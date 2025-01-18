use crate::{
    canister::{InputRune, OutputRune},
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
