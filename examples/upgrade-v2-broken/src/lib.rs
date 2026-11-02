#![no_std]
//! Breaking Upgrade Candidate Contract (v2) for SORARK (`sorark diff`).
//!
//! Demonstrates state-corrupting storage layout mutations and ABI breakages relative to `upgrade-v1`:
//! - `ARK-DIFF-001`: Renames `UserPosition.shares` -> `balance` and changes `lock_until` from `u64` -> `u32`.
//! - `ARK-DIFF-002`: Mutates `DataKey::Position(Address)` -> `DataKey::Position(Address, u32)`.
//! - `ARK-DIFF-003`: Alters `withdraw` parameter signature (`amount: i128` -> `amount: u64`).
//! - `ARK-DIFF-004`: Shifts `VaultError::InsufficientShares` numeric error code from `2` -> `1`.

use soroban_sdk::{
    Address, BytesN, Env, contract, contracterror, contractimpl, contracttype,
};

const DAY_IN_LEDGERS: u32 = 17_280;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    // Removed `Unauthorized = 1` and shifted `InsufficientShares` from 2 -> 1!
    InsufficientShares = 1,
    VaultPaused = 3,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPosition {
    pub owner: Address,
    // Renamed from `shares` -> `balance` (breaks ScMap key lookup on v1 ledger entries!)
    pub balance: i128,
    // Changed type from `u64` -> `u32` (traps on ScVal deserialization!)
    pub lock_until: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    Admin,
    TotalShares,
    // Added pool_id parameter to existing Position storage key variant!
    Position(Address, u32),
}

#[contract]
pub struct BrokenVaultV2;

#[contractimpl]
impl BrokenVaultV2 {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(DAY_IN_LEDGERS, DAY_IN_LEDGERS * 30);
    }

    pub fn deposit(env: Env, user: Address, shares: i128, lock_until: u64) -> i128 {
        user.require_auth();
        let pos = UserPosition {
            owner: user.clone(),
            balance: shares,
            lock_until: lock_until as u32,
        };
        let key = DataKey::Position(user, 0);
        env.storage().persistent().set(&key, &pos);
        env.storage()
            .persistent()
            .extend_ttl(&key, DAY_IN_LEDGERS, DAY_IN_LEDGERS * 30);
        shares
    }

    // Changed `amount` parameter from `i128` to `u64`
    pub fn withdraw(env: Env, user: Address, amount: u64) -> Result<i128, VaultError> {
        user.require_auth();
        let key = DataKey::Position(user, 0);
        let pos: UserPosition = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(VaultError::InsufficientShares)?;
        Ok(pos.balance - i128::from(amount))
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        env.storage()
            .instance()
            .extend_ttl(DAY_IN_LEDGERS, DAY_IN_LEDGERS * 30);
    }
}
