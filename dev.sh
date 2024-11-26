#!/usr/bin/env sh

dfx stop
dfx start --clean --background
dfx canister create rich-swap
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang dfx deploy rich-swap
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
      satoshis = 5_000 : nat64;
      balance = record {
        id = \"0:0\";
        value = 5_000 : nat;
      };
      txid = \"a44dcf3ead4106b3039f504fe976f9ea6133af43b948696a980120f037c860a1\";
      vout = 0 : nat32;
    },
    record {
      satoshis = 546 : nat64;
      balance = record {
        id = \"840001:431\";
        value = 2_200_000 : nat;
      };
      txid = \"d8bc1cd9a3aa2384847bc9f019332a125dae53bbfaebad169152a38cd288a188\";
      vout = 2 : nat32;
    },
    $p,
)"
