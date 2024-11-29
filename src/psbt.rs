use crate::{
    canister::{InputRune, OutputRune},
    CoinBalance, CoinId, ExchangeError, Pubkey, Txid, Utxo,
};
use bitcoin::{Psbt, Script};

pub(crate) fn extract_script(script: &Script) -> Option<Pubkey> {
    for inst in script.instructions() {
        match inst {
            Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes)) => {
                if bytes.len() == 33 {
                    return Some(
                        Pubkey::from_raw(bytes.as_bytes().to_vec())
                            .expect("pubkey must be compressed"),
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
) -> Result<Vec<(Utxo, Pubkey)>, ExchangeError> {
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
        let pubkey = extract_script(&witness.script_pubkey).ok_or(ExchangeError::InvalidPsbt(
            format!("unsupported input type: {}", i),
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
                r.push((utxo, pubkey));
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
                r.push((utxo, pubkey));
            }
        }
    }
    Ok(r)
}

pub(crate) fn outputs(
    txid: Txid,
    psbt: &Psbt,
    output_runes: &[OutputRune],
) -> Result<Vec<(Utxo, Pubkey)>, ExchangeError> {
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
            let pubkey = extract_script(&tx_out.script_pubkey);
            if pubkey.is_none() {
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
                    r.push((utxo, pubkey.unwrap()));
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
                    r.push((utxo, pubkey.unwrap()));
                }
            }
        }
    }
    Ok(r)
}
