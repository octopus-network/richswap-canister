// use candid::{CandidType, Deserialize};
// use ic_stable_structures::{storable::Bound, Storable};
// use ree_types_old::{exchange_interfaces::CoinBalance, CoinId, Pubkey, Txid};
// use serde::Serialize;
// use std::collections::BTreeMap;

#[allow(unused)]
pub(crate) fn migrate_to_v3() {
    let is_empty = crate::POOLS.with_borrow(|p| p.is_empty());
    if !is_empty {
        return;
    }
    crate::POOLS_V2.with(|p| {
        let pools = p.borrow().iter().map(|p| p.1.clone()).collect::<Vec<_>>();
        for pool in pools.into_iter() {
            let id = pool.meta.id;
            let addr = pool.addr.clone();
            let untweaked = pool.pubkey.clone();
            crate::POOL_TOKENS.with_borrow_mut(|l| {
                l.insert(id, addr.clone());
                crate::POOLS.with_borrow_mut(|p| {
                    p.insert(addr, pool);
                });
            });
        }
    });
}
