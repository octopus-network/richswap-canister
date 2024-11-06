#!/usr/bin/env sh

dfx stop
dfx start --clean --background
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang cargo build --release --target wasm32-unknown-unknown --features dev
dfx canister create rich-swap
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang dfx deploy rich-swap
#dfx canister install rich-swap --wasm target/wasm32-unknown-unknown/release/rich_swap.wasm -m reinstall -y
dfx canister call rich-swap create '(
    record {
        id = "0:0";
        symbol = "BTC";
        min_amount = "0.00000546";
        decimals = 8 : nat8;
    },
    record {
        id = "840001:431";
        symbol = "RICH";
        min_amount = "1";
        decimals = 2 : nat8;
    },
)' > pubkey.tmp
p=$(grep 'Ok' pubkey.tmp | tr -d ' ' | awk -F '=' '{print $2}')
if [ "$p" = "" ]; then
    echo "Failed to create pool"
    cat pubkey.tmp
    exit 1
fi
echo "pool id=$p"
dfx canister call rich-swap mock_add_liquidity "(
    record {
      satoshis = 24_000_000 : nat64;
      balance = record {
        id = \"0:0\";
        value = 24_000_000 : nat;
      };
      txid = \"18f71926c5795a28c9be1bd65f77db8f09399dcb5a3bc94424dc16ad7e3383cd\";
      vout = 0 : nat32;
    },
    record {
      satoshis = 546 : nat64;
      balance = record {
        id = \"840001:431\";
        value = 40_000_000_000 : nat;
      };
      txid = \"d66de939cb3ddb4d94f0949612e06e7a84d4d0be381d0220e2903aad68135969\";
      vout = 0 : nat32;
    },
    $p,
)"
