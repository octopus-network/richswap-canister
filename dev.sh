#!/usr/bin/env sh

# dfx stop
# dfx start --clean --background
# dfx canister create rich-swap
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang dfx deploy rich-swap --ic
dfx canister --ic call rich-swap create '(
    record {
        id = "0:0";
        symbol = "BTC";
        min_amount = "0.00000546";
        decimals = 8 : nat8;
    },
    record {
        id = "840000:846";
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
dfx canister call --ic rich-swap mock_add_liquidity "(
    record {
      satoshis = 4_916 : nat64;
      balance = record {
        id = \"0:0\";
        value = 4_916 : nat;
      };
      txid = \"63ca2c6acf5faf6a8d91e639e0a16bc85086d5aa95b7ec9a6dc9a5038834788d\";
      vout = 4 : nat32;
    },
    record {
      satoshis = 546 : nat64;
      balance = record {
        id = \"840000:846\";
        value = 2_866_667 : nat;
      };
      txid = \"63ca2c6acf5faf6a8d91e639e0a16bc85086d5aa95b7ec9a6dc9a5038834788d\";
      vout = 2 : nat32;
    },
    \"021774b3f1c2d9f8e51529eda4a54624e2f067826b42281fb5b9a9b40fd4a967e9\",
)"
