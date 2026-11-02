#![no_std]
//! Intentional Soroban storage-archival and upgrade-safety test fixture for SORARK.
//!
//! Running `sorark lint examples/vulnerable-vault` deterministically detects:
//! - `ARK-STOR-001`: Transitive unbounded `Map<Address, i128>` stored in `instance()` storage.
//! - `ARK-STOR-002`: Persistent storage mutation in `deposit` missing `extend_ttl`.
//! - `ARK-STOR-003`: Security-critical `TempAdmin` stored in ephemeral `temporary()` storage.
//! - `ARK-STOR-004`: Invalid `extend_ttl(50_000, 10_000)` where `threshold > extend_to`.
//! - `ARK-UPG-001`: Unauthenticated `update_current_contract_wasm` call.

use soroban_sdk::{Address, BytesN, Env, Map, contract, contractimpl, contracttype};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalRegistry {
    pub protocol_fee_bps: u32,
    /// Unbounded map embedded inside a struct that gets saved to `instance()` storage.
    pub historical_depositors: Map<Address, i128>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    Registry,
    TempAdmin,
    UserBalance(Address),
}

#[contract]
pub struct VulnerableVaultContract;

#[contractimpl]
impl VulnerableVaultContract {
    /// Triggers `ARK-STOR-001` (transitive unbounded struct in `instance` storage)
    /// and `ARK-STOR-003` (critical admin key in `temporary` storage).
    pub fn initialize_vulnerable(env: Env, admin: Address, registry: GlobalRegistry) {
        env.storage().instance().set(&DataKey::Registry, &registry);
        env.storage().temporary().set(&DataKey::TempAdmin, &admin);
        env.storage().instance().extend_ttl(4_096, 17_280);
    }

    /// Triggers `ARK-STOR-002` (writes to `persistent()` storage without extending TTL).
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::UserBalance(user);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Triggers `ARK-STOR-004` (`threshold` 50_000 > `extend_to` 10_000 traps on the Soroban host).
    pub fn broken_ttl_extension(env: Env) {
        env.storage().instance().extend_ttl(50_000, 10_000);
    }

    /// Triggers `ARK-UPG-001` (unprotected WASM bytecode replacement without `require_auth()`).
    pub fn unprotected_upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
