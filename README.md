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

## REE Tutorials

Coming soon.

## Audit Report
[blocksec](./audit_report/blocksec_omnity_richswap_v1.0-signed.pdf)

## License
[MIT](LICENSE)
