// This is the generated code for the Candid interface `Rune Indexer`
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub enum Result_ {
    Ok,
    Err(String),
}

#[derive(CandidType, Deserialize)]
pub struct OrdEtching {
    pub confirmations: u32,
    pub rune_id: String,
}

#[derive(CandidType, Deserialize)]
pub enum RpcError {
    Io(String, String, String),
    Endpoint(String, String, String),
    Decode(String, String, String),
}

#[derive(CandidType, Deserialize)]
pub enum MintError {
    Cap(candid::Nat),
    End(u64),
    Start(u64),
    Unmintable,
}

#[derive(CandidType, Deserialize)]
pub enum OrdError {
    Rpc(RpcError),
    Overflow,
    Params(String),
    NotEnoughConfirmations,
    RuneNotFound,
    Index(MintError),
    WrongBlockHash(String),
    Unrecoverable,
    OutPointNotFound,
    Recoverable { height: u32, depth: u32 },
    WrongBlockMerkleRoot(String),
}

#[derive(CandidType, Deserialize)]
pub enum Result1 {
    Ok(Option<OrdEtching>),
    Err(OrdError),
}

#[derive(CandidType, Deserialize)]
pub enum Result2 {
    Ok(u32, String),
    Err(OrdError),
}

#[derive(CandidType, Deserialize)]
pub struct OrdTerms {
    pub cap: Option<candid::Nat>,
    pub height: (Option<u64>, Option<u64>),
    pub offset: (Option<u64>, Option<u64>),
    pub amount: Option<candid::Nat>,
}

#[derive(CandidType, Deserialize)]
pub struct OrdRuneEntry {
    pub confirmations: u32,
    pub mints: candid::Nat,
    pub terms: Option<OrdTerms>,
    pub etching: String,
    pub turbo: bool,
    pub premine: candid::Nat,
    pub divisibility: u8,
    pub spaced_rune: String,
    pub number: u64,
    pub timestamp: u64,
    pub block: u64,
    pub burned: candid::Nat,
    pub symbol: Option<String>,
}

#[derive(CandidType, Deserialize)]
pub enum Result3 {
    Ok(OrdRuneEntry),
    Err(OrdError),
}

#[derive(CandidType, Deserialize)]
pub struct RuneId {
    pub tx: u32,
    pub block: u64,
}

#[derive(CandidType, Deserialize)]
pub struct RuneBalance {
    pub id: RuneId,
    pub balance: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum Result4 {
    Ok(Vec<RuneBalance>),
    Err(OrdError),
}

#[derive(CandidType, Deserialize)]
pub struct OrdRuneBalance {
    pub id: String,
    pub confirmations: u32,
    pub divisibility: u8,
    pub amount: candid::Nat,
    pub symbol: Option<String>,
}

#[derive(CandidType, Deserialize)]
pub enum Result5 {
    Ok(Vec<Option<Vec<OrdRuneBalance>>>),
    Err(OrdError),
}

pub struct Service(pub Principal);
impl Service {
    pub async fn add_subscriber(&self, arg0: String) -> Result<(Result_,)> {
        ic_cdk::call(self.0, "add_subscriber", (arg0,)).await
    }

    pub async fn get_etching(&self, arg0: String) -> Result<(Result1,)> {
        ic_cdk::call(self.0, "get_etching", (arg0,)).await
    }

    pub async fn get_height(&self) -> Result<(Result2,)> {
        ic_cdk::call(self.0, "get_height", ()).await
    }

    pub async fn get_rune_entry_by_rune_id(&self, arg0: String) -> Result<(Result3,)> {
        ic_cdk::call(self.0, "get_rune_entry_by_rune_id", (arg0,)).await
    }

    pub async fn get_runes_by_utxo(&self, arg0: String, arg1: u32) -> Result<(Result4,)> {
        ic_cdk::call(self.0, "get_runes_by_utxo", (arg0, arg1)).await
    }

    pub async fn get_subscribers(&self) -> Result<(Vec<String>,)> {
        ic_cdk::call(self.0, "get_subscribers", ()).await
    }

    pub async fn query_runes(&self, arg0: Vec<String>) -> Result<(Result5,)> {
        ic_cdk::call(self.0, "query_runes", (arg0,)).await
    }

    pub async fn set_url(&self, arg0: String) -> Result<(Result_,)> {
        ic_cdk::call(self.0, "set_url", (arg0,)).await
    }
}
