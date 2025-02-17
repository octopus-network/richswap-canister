use crate::{ExchangeError, Utxo};
use ree_types::bitcoin::{
    self,
    psbt::Psbt,
    sighash::{Prevouts, SighashCache},
    OutPoint, TapSighashType, Witness,
};

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
