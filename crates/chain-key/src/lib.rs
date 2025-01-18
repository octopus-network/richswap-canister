use candid::{CandidType, Principal};
use ic_cdk::api::management_canister::schnorr::SchnorrAlgorithm;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ManagementCanisterSchnorrPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ManagementCanisterSchnorrPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
struct ManagementCanisterSignatureRequest {
    pub message: Vec<u8>,
    pub aux: Option<SignWithSchnorrAux>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(Eq, PartialEq, Debug, CandidType, Serialize)]
pub enum SignWithSchnorrAux {
    #[serde(rename = "bip341")]
    Bip341(SignWithBip341Aux),
}

#[derive(Eq, PartialEq, Debug, CandidType, Serialize)]
pub struct SignWithBip341Aux {
    pub merkle_root_hash: ByteBuf,
}

#[derive(CandidType, Deserialize, Debug)]
struct ManagementCanisterSignatureReply {
    pub signature: Vec<u8>,
}

const MGMT_CANISTER_ID: &str = "aaaaa-aa";

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_text(MGMT_CANISTER_ID).unwrap()
}

pub async fn schnorr_pubkey(
    derive_path: Vec<u8>,
    key_id: impl ToString,
) -> Result<Vec<u8>, String> {
    let request = ManagementCanisterSchnorrPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![derive_path],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_id.to_string(),
        },
    };
    let (res,): (ManagementCanisterSchnorrPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "schnorr_public_key", (request,))
            .await
            .map_err(|e| format!("schnorr_public_key failed {}", e.1))?;
    Ok(res.public_key)
}

pub async fn schnorr_sign(
    message: Vec<u8>,
    derive_path: Vec<u8>,
    key_id: impl ToString,
    merkle_root: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let merkle_root_hash = merkle_root
        .map(|bytes| {
            if bytes.len() == 32 || bytes.is_empty() {
                Ok(ByteBuf::from(bytes))
            } else {
                Err(format!(
                    "merkle tree root bytes must be 0 or 32 bytes long but got {}",
                    bytes.len()
                ))
            }
        })
        .transpose()?
        .unwrap_or_default();
    let aux = Some(SignWithSchnorrAux::Bip341(SignWithBip341Aux {
        merkle_root_hash,
    }));
    let request = ManagementCanisterSignatureRequest {
        message,
        derivation_path: vec![derive_path],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_id.to_string(),
        },
        aux,
    };
    let (reply,): (ManagementCanisterSignatureReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
        "sign_with_schnorr",
        (request,),
        26_153_846_153,
    )
    .await
    .map_err(|e| format!("sign_with_schnorr failed {e:?}"))?;
    Ok(reply.signature)
}

// enum SchnorrKeyIds {
//     #[allow(unused)]
//     ChainkeyTestingCanisterKey1,
//     #[allow(unused)]
//     TestKeyLocalDevelopment,
//     #[allow(unused)]
//     TestKey1,
//     #[allow(unused)]
//     ProductionKey1,
// }

// impl SchnorrKeyIds {
//     fn to_key_id(&self, algorithm: SchnorrAlgorithm) -> SchnorrKeyId {
//         SchnorrKeyId {
//             algorithm,
//             name: match self {
//                 Self::ChainkeyTestingCanisterKey1 => "insecure_test_key_1",
//                 Self::TestKeyLocalDevelopment => "dfx_test_key_1",
//                 Self::TestKey1 => "test_key_1",
//                 Self::ProductionKey1 => "key_1",
//             }
//             .to_string(),
//         }
//     }
// }
