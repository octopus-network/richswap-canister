# RichSwap

> An AMM protocol for Bitcoin built on REE(Runes Exchange Environment).

Unlike Ethereum and other smart contract platforms, Bitcoin's scripting language is not Turing complete, making it extremely challenging—if not impossible—to develop complex applications like AMM protocols directly on the Bitcoin network using BTC scripts and the UTXO model.

REE overcomes this limitation by leveraging the powerful Chain Key technology of the Internet Computer Protocol (ICP) and Bitcoin's Partially Signed Bitcoin Transactions (PSBT) to extend the programmability of Bitcoin's Rune assets.

RichSwap is the first application to harness the capabilities of REE.

## How it works

RichSwap operates as an ICP canister, essentially functioning as a smart contract on the Internet Computer Protocol (ICP). Within the Runes Exchange Environment (REE) framework, it is referred to as an _Exchange_. At its core, RichSwap maintains multiple pools, which correspond to the liquidity pools found in traditional AMM protocols. Each pool is associated with a single UTXO(typically, it binds a bunch of Rune assets) on the Bitcoin network. The unlocking condition for this UTXO is tied to the ICP Chain Key signature, meaning the UTXO can only be spent with the authorization of the ICP Chain Key.

User interactions with RichSwap are primarily divided into three key actions, as is typical for AMM protocols: adding liquidity, withdrawing liquidity, and swapping. These operations are facilitated through Partially Signed Bitcoin Transactions (PSBT).

Here’s how the process works:

**Constructing the PSBT**: The client application (e.g., a wallet or interface) gathers the necessary information from RichSwap and constructs a PSBT based on the user’s input. The user then signs the PSBT to authorize the transaction.

**Submitting the PSBT to REE**: The client composes the signed PSBT and essential information retrieved in the previous step and submit to REE Orchestrator. REE will validate the PSBT(including the UTXOs and their RUNE information) and analysis the input-output relations. If all check pass, Orchestrator will forward the request to RichSwap.

**RichSwap’s Validation and Signing**: RichSwap verifies the transaction details from REE Orchestrator and, if everything is valid, signs the pool’s UTXO using the ICP Chain Key. This step transforms the PSBT into a fully valid Bitcoin transaction.

**Broadcasting the Transaction**: The finalized transaction is returned to the REE, which broadcasts it to the Bitcoin network for execution.

There is no need for cross-chain transfers or bridging, ensuring a seamless and secure experience while leveraging the unique capabilities of ICP and REE. This design not only simplifies the user experience but also enhances the security and efficiency of decentralized trading on Bitcoin.

## RichSwap Integration Guide

To interact with RichSwap, clients must have the capability to access ICP canisters and sign BTC PSBTs.

The [RichSwap canister](https://dashboard.internetcomputer.org/canister/kmwen-yaaaa-aaaar-qam3a-cai#interface) generates different language code to access RichSwap. You could also refer to the [RichSwap API docs](https://docs.omnity.network/docs/Rich-Swap/apis) for more details.

As an REE exchange, the client of RichSwap should follow the "inquiry/invoke" pattern to interact with RichSwap. All inquiry functions in RichSwap are start with "pre_". For example, to complete a swap transaction, the client must first invoke RichSwap's pre-swap interface to obtain a quote.

First, let's query the pools from RichSwap:
``` bash
# fetch the pool list
dfx canister call kmwen-yaaaa-aaaar-qam3a-cai --ic get_pool_list '(record {from=null;limit=100;},)'

```

Now we got the pool list. Let's try to swap 10000 sats to HOPE•YOU•GET•RICH. 
``` bash
# obtain a quote from pool HOPE•YOU•GET•RICH
dfx canister call kmwen-yaaaa-aaaar-qam3a-cai --ic pre_swap '("bc1ptnxf8aal3apeg8r4zysr6k2mhadg833se2dm4nssl7drjlqdh2jqa4tk3p", record {id="0:0"; value=10000;})'
```
In REE, `CoinId` represents a RUNE token. Specially, BTC is "0:0".

The canister replies:

``` bash
(
  variant {
    Ok = record {
      output = record { id = "840000:846"; value = 3_834_248 : nat };
      nonce = 1_147 : nat64;
      price_impact = 1 : nat32;
      input = record {
        coins = vec {
          record { id = "840000:846"; value = 64_183_732_378 : nat };
        };
        sats = 167_414_165 : nat64;
        txid = "115fd37d0622775daf2783228d2997e38c756bc1d99714d62e2f5c96e9714e42";
        vout = 1 : nat32;
      };
    }
  },
)
```
You could find the response definition on RichSwap dashboard mentioned above. Let's break it down here.

- The `output` is the offer that the pool provides. In the case, the pool tells us that we will get 3834248 "840000:846" which represents HOPE•YOU•GET•RICH.
- The `nonce` will be used later to submit `invoke`.
- The `input` is the UTXO of pool.

Now we have collected enough information, if we agree this offer, we could construct a PSBT and sign it.

The client could select arbitrary UTXOs within its wallet; naturally, we will also include change for ourselves in the output.

Assume we got 1 UTXO > 10000 sats(since the client must pay for the network fee), we could construct such a PSBT:

```bash
input #0: 115fd37d0622775daf2783228d2997e38c756bc1d99714d62e2f5c96e9714e42:1 (pool, unsigned) 167414167 sats
input #1: 9c1f8398f5a92eee44aee58d000a4dc1705f9c25e29683f7730215bc1274cff1:0 (client, signed) 20000 sats
--------------
output #0: 167414165 + 10000 sats to pool's pubbkey
output #1: OP_RETURN: allocate 64183732378 - 3834248 RUNE to #0; allocate 3834248 to RUNE #2
output #2: 9000 sats to client's pubkey
```

After we signed this PSBT, we should serialize it and submit to REE. Since the actuall PSBT might be more complicated than this one, REE requires some extra information to validate the whole transaction. Below is the full parameter of REE `invoke` function:

``` rust
type Intention = record {
  input_coins : vec InputCoin;
  output_coins : vec OutputCoin;
  action : text;
  exchange_id : text;
  action_params : text;
  nonce : nat64;
  pool_address : text;
  pool_utxo_spent : vec text;
  pool_utxo_received : vec Utxo;
};

type IntentionSet = record {
  tx_fee_in_sats : nat64;
  initiator_address : text;
  intentions : vec Intention;
};

type InvokeArgs = record {
  intention_set : IntentionSet;
  initiator_utxo_proof : blob;
  psbt_hex : text;
};
```
The definition seems a little bit complicated, but we only need to fill part of it.

- The `input_coins` is the what we passed in the first step, i.e. "0:0" + 10000 sats.
- The `output_coins` is the result of the second step, i.e. how much RUNE we can get.
- The `action` is decided by the RichSwap since REE is a general protocol for extending BTC's capacity. Different functions have different action. In this scenario, it is "swap".
- The `exchange_id` is "RICH_SWAP".
- The `action_params` should be empty in this case.
- The `nonce` should be value just returned from RichSwap pool. In this case, it is 1147.
- The `pool_address` is "bc1ptnxf8aal3apeg8r4zysr6k2mhadg833se2dm4nssl7drjlqdh2jqa4tk3p" in this case.
- The `pool_utxo_spent` and `pool_utxo_received` are both empty since REE will infer them from PSBT.
- The `initiator_address` is the caller address. In this case, it is the owner of input #1.

Note that REE supports multiple transaction, so there is a `intention_set` rather than a single `intention` field. 

Now we could submit the tx to REE and it will automatically broadcast it to BTC network.

``` bash
dfx canister call kqs64-paaaa-aaaar-qamza-cai --ic invoke '...'
```

## Audit Report
[blocksec](./audit_report/blocksec_omnity_richswap_v1.0-signed.pdf)

## License
[MIT](LICENSE)
