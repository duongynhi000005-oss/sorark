//! Stellar Mainnet protocol constants for state archival TTL bounds and ledger entry sizes.

/// Stellar Mainnet minimum TTL for temporary entries (`16` ledgers, ~80 seconds).
pub const MAINNET_MIN_TEMP_ENTRY_TTL: u32 = 16;

/// Stellar Mainnet minimum TTL for persistent/instance entries (`4,096` ledgers, ~5.6 hours).
pub const MAINNET_MIN_PERSISTENT_ENTRY_TTL: u32 = 4_096;

/// Stellar Mainnet maximum TTL for any ledger entry (`3,110,400` ledgers, ~180 days).
pub const MAINNET_MAX_ENTRY_TTL: u32 = 3_110_400;

/// Default WASM binary size warning threshold (`48 KiB`).
pub const DEFAULT_WASM_WARN_BYTES: usize = 49_152;

/// Stellar Mainnet ledger entry hard size limit (`64 KiB`).
pub const MAINNET_LEDGER_ENTRY_MAX_BYTES: usize = 65_536;
