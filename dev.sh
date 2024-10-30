#!/usr/bin/env sh

dfx deploy rich-swap --argument "(
  record {
    x = record {
      satoshis = 24_000_000 : nat64;
      balance = record {
        id = record { tx = 0 : nat32; block = 0 : nat64 };
        value = 24_000_000 : nat;
      };
      txid = \"18f71926c5795a28c9be1bd65f77db8f09399dcb5a3bc94424dc16ad7e3383cd\";
      vout = 0 : nat32;
    };
    y = record {
      satoshis = 546 : nat64;
      balance = record {
        id = record { tx = 431 : nat32; block = 840_001 : nat64 };
        value = 40_000_000_000 : nat;
      };
      txid = \"d66de939cb3ddb4d94f0949612e06e7a84d4d0be381d0220e2903aad68135969\";
      vout = 0 : nat32;
    };
    addr = \"bc1p2rquanq5xgs8gwwvrp7kna9ptpqq6pjq4x7x4agfx0kfhf7sqrmsjaf8kh\";
  },
)"
