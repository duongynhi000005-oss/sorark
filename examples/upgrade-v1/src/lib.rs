#![no_std]
//! Production-safe Baseline Vault Contract (v1) for SORARK.
//!
//! Passes `sorark lint examples/upgrade-v1` with zero errors or warnings, and serves
//! as the `--old` baseline when testing `sorark diff` against `examples/upgrade-v2-broken`.

use soroban_sdk::{
    Address, BytesN, Env, contract, contracterror, contractimpl, contracttype,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 7;
const INSTANCE_TTL_EXTEND: u32 = DAY_IN_LEDGERS * 30;
const PERSISTENT_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 14;
const PERSISTENT_TTL_EXTEND: u32 = DAY_IN_LEDGERS * 90;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    Unauthorized = 1,
    InsufficientShares = 2,
    VaultPaused = 3,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPosition {
    pub owner: Address,
    pub shares: i128,
    pub lock_until: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    Admin,
    TotalShares,
    Position(Address),
}

#[contract]
pub struct SafeVaultV1;

#[contractimpl]
impl SafeVaultV1 {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::TotalShares, &0_i128);
        bump_instance_ttl(&env);
    }

    pub fn deposit(env: Env, user: Address, shares: i128, lock_until: u64) -> i128 {
        user.require_auth();
        let pos = UserPosition {
            owner: user.clone(),
            shares,
            lock_until,
        };
        let key = DataKey::Position(user.clone());
        env.storage().persistent().set(&key, &pos);
        bump_position_ttl(&env, &user);

        let total: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);
        let new_total = total + shares;
        env.storage()
            .instance()
            .set(&DataKey::TotalShares, &new_total);
        bump_instance_ttl(&env);
        new_total
    }

    pub fn withdraw(env: Env, user: Address, amount: i128) -> Result<i128, VaultError> {
        user.require_auth();
        let key = DataKey::Position(user.clone());
        let mut pos: UserPosition = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(VaultError::InsufficientShares)?;
        if pos.shares < amount {
            return Err(VaultError::InsufficientShares);
        }
        pos.shares -= amount;
        env.storage().persistent().set(&key, &pos);
        bump_position_ttl(&env, &user);
        Ok(pos.shares)
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        require_admin(&env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        bump_instance_ttl(&env);
    }
}

fn require_admin(env: &Env) {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);
}

fn bump_position_ttl(env: &Env, user: &Address) {
    env.storage().persistent().extend_ttl(
        &DataKey::Position(user.clone()),
        PERSISTENT_TTL_THRESHOLD,
        PERSISTENT_TTL_EXTEND,
    );
}

