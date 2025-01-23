// This is an experimental feature to generate Rust binding from Candid.
// You may want to manually adjust some of the types.
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub struct GetEtchingResult {
    pub confirmations: u32,
    pub rune_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct Terms {
    pub cap: Option<candid::Nat>,
    pub height: (Option<u64>, Option<u64>),
    pub offset: (Option<u64>, Option<u64>),
    pub amount: Option<candid::Nat>,
}

#[derive(CandidType, Deserialize)]
pub struct RuneEntry {
    pub confirmations: u32,
    pub mints: candid::Nat,
    pub terms: Option<Terms>,
    pub etching: String,
    pub turbo: bool,
    pub premine: candid::Nat,
    pub divisibility: u8,
    pub spaced_rune: String,
    pub number: u64,
    pub timestamp: u64,
    pub block: u64,
    pub burned: candid::Nat,
    pub rune_id: String,
    pub symbol: Option<String>,
}

#[derive(CandidType, Deserialize)]
pub struct RuneBalance {
    pub confirmations: u32,
    pub divisibility: u8,
    pub amount: candid::Nat,
    pub rune_id: String,
    pub symbol: Option<String>,
}

#[derive(CandidType, Deserialize)]
pub enum Error {
    MaxOutpointsExceeded,
}

#[derive(CandidType, Deserialize)]
pub enum Result_ {
    Ok(Vec<Option<Vec<RuneBalance>>>),
    Err(Error),
}

pub struct Service(pub Principal);
impl Service {
    pub async fn get_etching(&self, arg0: String) -> Result<(Option<GetEtchingResult>,)> {
        ic_cdk::call(self.0, "get_etching", (arg0,)).await
    }

    pub async fn get_latest_block(&self) -> Result<(u32, String)> {
        ic_cdk::call(self.0, "get_latest_block", ()).await
    }

    pub async fn get_rune(&self, arg0: String) -> Result<(Option<RuneEntry>,)> {
        ic_cdk::call(self.0, "get_rune", (arg0,)).await
    }

    pub async fn get_rune_balances_for_outputs(&self, arg0: Vec<String>) -> Result<(Result_,)> {
        ic_cdk::call(self.0, "get_rune_balances_for_outputs", (arg0,)).await
    }

    pub async fn get_rune_by_id(&self, arg0: String) -> Result<(Option<RuneEntry>,)> {
        ic_cdk::call(self.0, "get_rune_by_id", (arg0,)).await
    }
}
