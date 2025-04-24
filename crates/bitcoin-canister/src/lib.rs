#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub enum Flag {
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "enabled")]
    Enabled,
}

#[derive(CandidType, Deserialize)]
pub struct Fees {
    pub get_current_fee_percentiles: candid::Nat,
    pub get_utxos_maximum: candid::Nat,
    pub get_block_headers_cycles_per_ten_instructions: candid::Nat,
    pub get_current_fee_percentiles_maximum: candid::Nat,
    pub send_transaction_per_byte: candid::Nat,
    pub get_balance: candid::Nat,
    pub get_utxos_cycles_per_ten_instructions: candid::Nat,
    pub get_block_headers_base: candid::Nat,
    pub get_utxos_base: candid::Nat,
    pub get_balance_maximum: candid::Nat,
    pub send_transaction_base: candid::Nat,
    pub get_block_headers_maximum: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum Network {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "regtest")]
    Regtest,
    #[serde(rename = "testnet")]
    Testnet,
}

#[derive(CandidType, Deserialize)]
pub struct InitConfig {
    pub api_access: Option<Flag>,
    pub lazily_evaluate_fee_percentiles: Option<Flag>,
    pub blocks_source: Option<Principal>,
    pub fees: Option<Fees>,
    pub watchdog_canister: Option<Option<Principal>>,
    pub network: Option<Network>,
    pub stability_threshold: Option<candid::Nat>,
    pub syncing: Option<Flag>,
    pub burn_cycles: Option<Flag>,
    pub disable_api_if_not_fully_synced: Option<Flag>,
}

pub type Address = String;
#[derive(CandidType, Deserialize)]
pub struct GetBalanceRequest {
    pub network: Network,
    pub address: Address,
    pub min_confirmations: Option<u32>,
}

pub type Satoshi = u64;
pub type BlockHeight = u32;
#[derive(CandidType, Deserialize)]
pub struct GetBlockHeadersRequest {
    pub start_height: BlockHeight,
    pub end_height: Option<BlockHeight>,
    pub network: Network,
}

pub type BlockHeader = serde_bytes::ByteBuf;
#[derive(CandidType, Deserialize)]
pub struct GetBlockHeadersResponse {
    pub tip_height: BlockHeight,
    pub block_headers: Vec<BlockHeader>,
}

#[derive(CandidType, Deserialize)]
pub struct GetCurrentFeePercentilesRequest {
    pub network: Network,
}

pub type MillisatoshiPerByte = u64;
#[derive(CandidType, Deserialize)]
pub enum GetUtxosRequestFilterInner {
    #[serde(rename = "page")]
    Page(serde_bytes::ByteBuf),
    #[serde(rename = "min_confirmations")]
    MinConfirmations(u32),
}

#[derive(CandidType, Deserialize)]
pub struct GetUtxosRequest {
    pub network: Network,
    pub filter: Option<GetUtxosRequestFilterInner>,
    pub address: Address,
}

pub type BlockHash = serde_bytes::ByteBuf;
#[derive(CandidType, Deserialize)]
pub struct Outpoint {
    pub txid: serde_bytes::ByteBuf,
    pub vout: u32,
}

#[derive(CandidType, Deserialize)]
pub struct Utxo {
    pub height: BlockHeight,
    pub value: Satoshi,
    pub outpoint: Outpoint,
}

#[derive(CandidType, Deserialize)]
pub struct GetUtxosResponse {
    pub next_page: Option<serde_bytes::ByteBuf>,
    pub tip_height: BlockHeight,
    pub tip_block_hash: BlockHash,
    pub utxos: Vec<Utxo>,
}

#[derive(CandidType, Deserialize)]
pub struct SendTransactionRequest {
    pub transaction: serde_bytes::ByteBuf,
    pub network: Network,
}

#[derive(CandidType, Deserialize)]
pub struct Config {
    pub api_access: Flag,
    pub lazily_evaluate_fee_percentiles: Flag,
    pub blocks_source: Principal,
    pub fees: Fees,
    pub watchdog_canister: Option<Principal>,
    pub network: Network,
    pub stability_threshold: candid::Nat,
    pub syncing: Flag,
    pub burn_cycles: Flag,
    pub disable_api_if_not_fully_synced: Flag,
}

#[derive(CandidType, Deserialize)]
pub struct SetConfigRequest {
    pub api_access: Option<Flag>,
    pub lazily_evaluate_fee_percentiles: Option<Flag>,
    pub fees: Option<Fees>,
    pub watchdog_canister: Option<Option<Principal>>,
    pub stability_threshold: Option<candid::Nat>,
    pub syncing: Option<Flag>,
    pub burn_cycles: Option<Flag>,
    pub disable_api_if_not_fully_synced: Option<Flag>,
}

pub struct Service(pub Principal);
impl Service {
    pub async fn bitcoin_get_balance(&self, arg0: GetBalanceRequest) -> Result<(Satoshi,)> {
        ic_cdk::call(self.0, "bitcoin_get_balance", (arg0,)).await
    }

    pub async fn bitcoin_get_balance_query(&self, arg0: GetBalanceRequest) -> Result<(Satoshi,)> {
        ic_cdk::call(self.0, "bitcoin_get_balance_query", (arg0,)).await
    }

    pub async fn bitcoin_get_block_headers(
        &self,
        arg0: GetBlockHeadersRequest,
    ) -> Result<(GetBlockHeadersResponse,)> {
        ic_cdk::call(self.0, "bitcoin_get_block_headers", (arg0,)).await
    }

    pub async fn bitcoin_get_current_fee_percentiles(
        &self,
        arg0: GetCurrentFeePercentilesRequest,
    ) -> Result<(Vec<MillisatoshiPerByte>,)> {
        ic_cdk::call(self.0, "bitcoin_get_current_fee_percentiles", (arg0,)).await
    }

    pub async fn bitcoin_get_utxos(&self, arg0: GetUtxosRequest) -> Result<(GetUtxosResponse,)> {
        ic_cdk::call(self.0, "bitcoin_get_utxos", (arg0,)).await
    }

    pub async fn bitcoin_get_utxos_query(
        &self,
        arg0: GetUtxosRequest,
    ) -> Result<(GetUtxosResponse,)> {
        ic_cdk::call(self.0, "bitcoin_get_utxos_query", (arg0,)).await
    }

    pub async fn bitcoin_send_transaction(&self, arg0: SendTransactionRequest) -> Result<()> {
        ic_cdk::call(self.0, "bitcoin_send_transaction", (arg0,)).await
    }

    pub async fn get_config(&self) -> Result<(Config,)> {
        ic_cdk::call(self.0, "get_config", ()).await
    }

    pub async fn set_config(&self, arg0: SetConfigRequest) -> Result<()> {
        ic_cdk::call(self.0, "set_config", (arg0,)).await
    }
}
