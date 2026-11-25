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
            code: match code_opt {
                Some(c) => Some(
                    Bytecode::new_raw_checked(Bytes::from(c))
                        .map_err(|e| format!("invalid bytecode: {e:?}"))?,
                ),
                None => None,
            },
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

    // Store reenter_calldata words into memory at 0.. using PUSH2 16-bit offsets (capped at 4 KiB)
    let bounded_cd = &reenter_calldata[..reenter_calldata.len().min(4096)];
    for (chunk_idx, chunk) in bounded_cd.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        code.push(0x7f); // PUSH32
        code.extend_from_slice(&word);
        let mem_off = (chunk_idx * 32) as u16;
        code.push(0x61); // PUSH2
        code.extend_from_slice(&mem_off.to_be_bytes());
        code.push(0x52); // MSTORE
    }
    let cd_len = bounded_cd.len() as u16;
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

/// Known DeFi/NFT callback selectors that trigger reentrant execution (`onERC721Received`,
/// `onFlashLoan`, `uniswapV3SwapCallback`).
pub const SEL_ON_ERC721_RECEIVED: [u8; 4] = [0x15, 0x0b, 0x7a, 0x02];
pub const SEL_ON_FLASH_LOAN: [u8; 4] = [0x23, 0xe3, 0x0c, 0x8b];
pub const SEL_UNIV3_SWAP_CALLBACK: [u8; 4] = [0xfa, 0x46, 0x1e, 0x33];

/// Builds a callback-aware reentrant attacker EVM bytecode that handles `onERC721Received`,
/// `onFlashLoan`, and `uniswapV3SwapCallback` (returning the expected ERC-721/ERC-3156 magic
/// selector) while re-entering `VICTIM_ADDR` with `reenter_calldata` up to `max_reentries` times.
pub fn build_callback_reentrant_attacker(
    callback_selector: [u8; 4],
    magic_return: [u8; 32],
    max_reentries: u8,
    reenter_calldata: &[u8],
) -> Vec<u8> {
    let mut code = Vec::new();
    // If CALLDATASIZE < 4 -> jump to callback_pc (ETH receive);
    // else if first 4 bytes == callback_selector -> jump to callback_pc;
    // else -> forwarder branch.
    code.extend_from_slice(&[0x60, 0x04, 0x36, 0x10]); // PUSH1 4, CALLDATASIZE, LT (CALLDATASIZE < 4)
    let small_cd_jump_idx = code.len() + 1;
    code.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 callback_pc, JUMPI

    // Compare first 4 bytes of calldata against callback_selector
    code.extend_from_slice(&[0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c]); // PUSH1 0, CALLDATALOAD, PUSH1 224, SHR
    code.push(0x63);
    code.extend_from_slice(&callback_selector); // PUSH4 callback_selector
    code.push(0x14); // EQ
    let cb_match_jump_idx = code.len() + 1;
    code.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 callback_pc, JUMPI

    // Forwarder branch: forward calldata + value to VICTIM_ADDR
    code.extend_from_slice(&[
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY
        0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00, 0x34, // ret/arg/value
        0x61, 0x20, 0x00, // VICTIM_ADDR
        0x62, 0x1e, 0x84, 0x80, 0xf1, // PUSH3 2_000_000, CALL
        0x50, 0x00, // POP, STOP
    ]);

    // Callback branch: increment slot[0]; if <= max_reentries, call VICTIM_ADDR(reenter_calldata); return magic_return
    let callback_pc = code.len() as u16;
    code[small_cd_jump_idx..small_cd_jump_idx + 2].copy_from_slice(&callback_pc.to_be_bytes());
    code[cb_match_jump_idx..cb_match_jump_idx + 2].copy_from_slice(&callback_pc.to_be_bytes());
    code.extend_from_slice(&[
        0x5b, // JUMPDEST (callback_pc)
        0x60,
        0x00,
        0x54, // SLOAD(0)
        0x60,
        0x01,
        0x01, // ADD 1
        0x80,
        0x60,
        0x00,
        0x55, // DUP1, SSTORE(0)
        0x60,
        max_reentries,
        0x90, // SWAP1
        0x11, // GT (count > max_reentries)
    ]);
    let ret_jump_idx = code.len() + 1;
    code.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 ret_pc, JUMPI

    // Copy reenter_calldata into memory using PUSH2 16-bit offsets (capped at 4 KiB) and CALL VICTIM_ADDR
    let bounded_cd = &reenter_calldata[..reenter_calldata.len().min(4096)];
    for (chunk_idx, chunk) in bounded_cd.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        code.push(0x7f);
        code.extend_from_slice(&word);
        let mem_off = (chunk_idx * 32) as u16;
        code.push(0x61); // PUSH2
        code.extend_from_slice(&mem_off.to_be_bytes());
        code.push(0x52); // MSTORE
    }
    let cd_len = bounded_cd.len() as u16;
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00]);
    code.push(0x61);
    code.extend_from_slice(&cd_len.to_be_bytes());
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x61, 0x20, 0x00]);
    code.extend_from_slice(&[0x62, 0x0c, 0x35, 0x00, 0xf1, 0x50]); // CALL(800_000), POP

    // Return magic 32-byte word (e.g. `onERC721Received.selector` padded in MSB)
    let ret_pc = code.len() as u16;
    code[ret_jump_idx..ret_jump_idx + 2].copy_from_slice(&ret_pc.to_be_bytes());
    code.push(0x5b); // JUMPDEST (ret_pc)
    code.push(0x7f); // PUSH32 magic_return
    code.extend_from_slice(&magic_return);
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]); // MSTORE(0), RETURN(0, 32)
    code
}

/// Probes compiled bytecode for **Read-Only View Reentrancy** inside in-process `revm`:
/// invokes `view_calldata` during the mid-execution reentrant callback (storing the observed
/// 32-byte return value in attacker slot `1`), then calls `view_calldata` again post-transaction.
/// If the mid-execution view value differs from the post-transaction steady-state value, the
/// view-oracle manipulation is **PROVEN**.
pub fn probe_view_reentrancy_in_revm(
    deployed_bytecode: &[u8],
    mutator_calldata: &[u8],
    view_calldata: &[u8],
) -> RevmWitnessResult {
    if deployed_bytecode.is_empty() || view_calldata.is_empty() {
        return RevmWitnessResult {
            proven: false,
            drained_wei: U256::ZERO,
            profit_wei: U256::ZERO,
            gas_used: 0,
            summary: "missing bytecode or view calldata".into(),
        };
    }

    // Build attacker bytecode:
    // - CALLDATASIZE == 0 -> ETH receive callback: STATICCALL VICTIM_ADDR(view_calldata) -> SSTORE(1), SSTORE(2, 1)
    // - CALLDATASIZE == 1 -> post-tx steady-state probe: STATICCALL VICTIM_ADDR(view_calldata) -> SSTORE(3)
    // - CALLDATASIZE >= 2 -> forward mutator calldata to VICTIM_ADDR
    let mut attacker = Vec::new();
    attacker.extend_from_slice(&[0x60, 0x01, 0x36, 0x11]); // PUSH1 1, CALLDATASIZE, GT (CALLDATASIZE > 1)
    let fwd_jump_idx = attacker.len() + 1;
    attacker.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 fwd_pc, JUMPI

    // Both CALLDATASIZE==0 (mid-callback) and CALLDATASIZE==1 (post-tx) run STATICCALL VICTIM_ADDR(view_calldata)
    let bounded_view = &view_calldata[..view_calldata.len().min(4096)];
    for (chunk_idx, chunk) in bounded_view.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        attacker.push(0x7f);
        attacker.extend_from_slice(&word);
        let mem_off = (chunk_idx * 32) as u16;
        attacker.push(0x61); // PUSH2
        attacker.extend_from_slice(&mem_off.to_be_bytes());
        attacker.push(0x52); // MSTORE
    }
    let vlen = bounded_view.len() as u16;
    // Place return buffer strictly past padded view_calldata so >64-byte view calldata never collides
    let ret_off: u16 = ((bounded_view.len().div_ceil(32) * 32) as u16).max(0x40);
    attacker.push(0x60);
    attacker.push(0x20); // retSize=32
    attacker.push(0x61);
    attacker.extend_from_slice(&ret_off.to_be_bytes()); // retOff
    attacker.push(0x61);
    attacker.extend_from_slice(&vlen.to_be_bytes()); // argSize
    attacker.extend_from_slice(&[0x60, 0x00, 0x61, 0x20, 0x00]); // argOff=0, VICTIM_ADDR
    attacker.extend_from_slice(&[0x62, 0x07, 0xa1, 0x20, 0xfa, 0x50]); // PUSH3 500_000, STATICCALL, POP
    // If CALLDATASIZE == 1 -> store into slot[3]; else -> store into slot[1] and mark slot[2] = 1
    attacker.extend_from_slice(&[0x36, 0x60, 0x01, 0x14]); // CALLDATASIZE == 1
    let post_jump_idx = attacker.len() + 1;
    attacker.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 post_pc, JUMPI
    attacker.push(0x61);
    attacker.extend_from_slice(&ret_off.to_be_bytes());
    attacker.extend_from_slice(&[0x51, 0x60, 0x01, 0x55]); // MLOAD(ret_off), SSTORE(1)
    attacker.extend_from_slice(&[0x60, 0x01, 0x60, 0x02, 0x55, 0x00]); // SSTORE(2, 1), STOP

    let post_pc = attacker.len() as u16;
    attacker[post_jump_idx..post_jump_idx + 2].copy_from_slice(&post_pc.to_be_bytes());
    attacker.push(0x5b); // JUMPDEST
    attacker.push(0x61);
    attacker.extend_from_slice(&ret_off.to_be_bytes());
    attacker.extend_from_slice(&[0x51, 0x60, 0x03, 0x55, 0x00]); // MLOAD(ret_off), SSTORE(3), STOP

    let fwd_pc = attacker.len() as u16;
    attacker[fwd_jump_idx..fwd_jump_idx + 2].copy_from_slice(&fwd_pc.to_be_bytes());
    attacker.extend_from_slice(&[
        0x5b, // JUMPDEST
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY
        0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00, 0x34, // ret/arg/value
        0x61, 0x20, 0x00, // VICTIM_ADDR
        0x62, 0x1e, 0x84, 0x80, 0xf1, 0x50, 0x00, // CALL(2_000_000), POP, STOP
    ]);

    let five_eth = U256::from(5_000_000_000_000_000_000u128);
    let accounts = vec![
        (EOA_ADDR, five_eth, None, vec![]),
        (
            VICTIM_ADDR,
            five_eth,
            Some(deployed_bytecode.to_vec()),
            vec![],
        ),
        (ATTACKER_ADDR, U256::ZERO, Some(attacker), vec![]),
    ];
    let txs = vec![
        CallProbeSpec {
            caller: EOA_ADDR,
            target: ATTACKER_ADDR,
            value: U256::ZERO,
            data: mutator_calldata.to_vec(),
        },
        CallProbeSpec {
            caller: EOA_ADDR,
            target: ATTACKER_ADDR,
            value: U256::ZERO,
            data: vec![0x01],
        },
    ];

    match execute_revm_sequence(accounts, &txs) {
        Ok((gas_used, _, db)) => {
            let cb_hit = db
                .cache
                .accounts
                .get(&ATTACKER_ADDR)
                .and_then(|a| a.storage.get(&U256::from(2)))
                .copied()
                .unwrap_or(U256::ZERO);
            let mid_val = db
                .cache
                .accounts
                .get(&ATTACKER_ADDR)
                .and_then(|a| a.storage.get(&U256::from(1)))
                .copied()
                .unwrap_or(U256::ZERO);
            let post_val = db
                .cache
                .accounts
                .get(&ATTACKER_ADDR)
                .and_then(|a| a.storage.get(&U256::from(3)))
                .copied()
                .unwrap_or(U256::ZERO);
            let proven = cb_hit != U256::ZERO && mid_val != post_val;
            RevmWitnessResult {
                proven,
                drained_wei: U256::ZERO,
                profit_wei: mid_val.abs_diff(post_val),
                gas_used,
                summary: if proven {
                    format!(
                        "revm PROVEN Read-Only View Reentrancy: mid-callback view={mid_val} != post-tx view={post_val} (gas={gas_used})"
                    )
                } else {
                    format!(
                        "view reentrancy probe observed consistent view state (cb_hit={cb_hit}, gas={gas_used})"
                    )
                },
            }
        }
        Err(err) => RevmWitnessResult {
            proven: false,
            drained_wei: U256::ZERO,
            profit_wei: U256::ZERO,
            gas_used: 0,
            summary: format!("revm view reentrancy probe error: {err}"),
        },
    }
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
            code: Bytecode::new_raw_checked(Bytes::from(deployed_bytecode.to_vec())).ok(),
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
    // Count storage slots whose committed value changed from 0, PLUS zero-storage ETH drains
    // (`SELFDESTRUCT` or positive-value `CALL` transferring ETH out of `target` to `EOA_ADDR`).
    let eoa_post_bal = db
        .cache
        .accounts
        .get(&EOA_ADDR)
        .map(|a| a.info.balance)
        .unwrap_or(U256::ZERO);
    let mut storage_writes = db
        .cache
        .accounts
        .get(&target)
        .map(|a| {
            let mut changed = a.storage.values().filter(|&&v| v != U256::ZERO).count();
            if a.info.balance != one_eth || a.info.is_empty_code_hash() {
                changed += 1;
            }
            changed
        })
        .unwrap_or(1);
    if storage_writes == 0 && eoa_post_bal > one_eth {
        storage_writes = 1;
    }
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

// ---------------------------------------------------------------------------
// Phase 15D: Stateful Multi-Tx `revm` Invariant Verifier & Sequence Shrinker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantTxStep {
    pub caller: Address,
    pub selector: [u8; 4],
    pub value_wei: U256,
    pub calldata: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InvariantCampaignConfig {
    pub seed: u64,
    pub sequences: usize,
    pub max_steps: usize,
    pub initial_contract_wei: U256,
    pub initial_storage: Vec<(U256, U256)>,
    pub protected_slot: Option<(U256, U256)>,
    pub selectors: Vec<[u8; 4]>,
}

#[derive(Debug, Clone)]
pub struct InvariantCampaignResult {
    pub violated: bool,
    pub invariant_name: Option<String>,
    pub sequences_run: usize,
    pub txs_executed: usize,
    pub minimal_trace: Vec<InvariantTxStep>,
    pub summary: String,
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = if *state == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        *state
    };
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn replay_invariant_sequence(
    deployed_bytecode: &[u8],
    cfg: &InvariantCampaignConfig,
    trace: &[InvariantTxStep],
) -> Option<String> {
    let target = VICTIM_ADDR;
    let mut db = InMemoryDB::default();
    let actor_balance = U256::from(10_000_000_000_000_000_000u128);
    for idx in 0..3u8 {
        let addr = Address::new([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, idx,
        ]);
        db.insert_account_info(
            addr,
            AccountInfo {
                balance: actor_balance,
                ..Default::default()
            },
        );
    }
    db.insert_account_info(
        target,
        AccountInfo {
            balance: cfg.initial_contract_wei,
            code: Bytecode::new_raw_checked(Bytes::from(deployed_bytecode.to_vec())).ok(),
            ..Default::default()
        },
    );
    for &(slot, val) in &cfg.initial_storage {
        let _ = db.insert_account_storage(target, slot, val);
    }

    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let mut cumulative_deposits = U256::ZERO;
    let mut nonces: std::collections::HashMap<Address, u64> = std::collections::HashMap::new();
    let actors = [
        Address::from([0xA1; 20]),
        Address::from([0xB2; 20]),
        Address::from([0xC3; 20]),
    ];

    for (step_idx, step) in trace.iter().enumerate() {
        let cur_nonce = *nonces.entry(step.caller).or_insert(0);
        let tx = TxEnv {
            caller: step.caller,
            kind: TxKind::Call(target),
            gas_limit: 2_000_000,
            value: step.value_wei,
            data: Bytes::from(step.calldata.clone()),
            nonce: cur_nonce,
            ..Default::default()
        };
        if let Ok(exec_res) = evm.transact_commit(tx) {
            *nonces.entry(step.caller).or_insert(0) = cur_nonce.saturating_add(1);
            if matches!(exec_res, ExecutionResult::Success { .. }) {
                cumulative_deposits = cumulative_deposits.saturating_add(step.value_wei);
            }
        }

        let db_ref = &evm.ctx.journaled_state.database;
        let current_bal = db_ref
            .cache
            .accounts
            .get(&target)
            .map(|a| a.info.balance)
            .unwrap_or(U256::ZERO);

        // Require attacker EOA net balance gain (`attacker_post > attacker_pre`) so protocol
        // fee/burn transfers to a treasury address do not trigger false SOLVENCY_BREACH alerts.
        let attacker_gained = actors.iter().any(|actor| {
            db_ref
                .cache
                .accounts
                .get(actor)
                .is_some_and(|a| a.info.balance > actor_balance)
        });

        if current_bal < cfg.initial_contract_wei && attacker_gained {
            return Some(format!(
                "SOLVENCY_BREACH at step {}: balance {} < initial reserve {} (deposited {})",
                step_idx + 1,
                current_bal,
                cfg.initial_contract_wei,
                cumulative_deposits
            ));
        }

        if let Some((slot, expected)) = cfg.protected_slot {
            let current_val = db_ref
                .cache
                .accounts
                .get(&target)
                .and_then(|a| a.storage.get(&slot).copied())
                .unwrap_or(U256::ZERO);
            if current_val != expected {
                return Some(format!(
                    "PROTECTED_SLOT_MUTATION at step {}: slot {} changed from {} to {}",
                    step_idx + 1,
                    slot,
                    expected,
                    current_val
                ));
            }
        }
    }
    None
}

/// Runs a deterministic seeded multi-transaction invariant verification campaign inside in-process
/// `revm`, checking solvency and protected-slot invariants across stateful sequences, and shrinks
/// any failing sequence down to a minimal reproducing trace.
pub fn run_stateful_revm_invariant_campaign(
    deployed_bytecode: &[u8],
    cfg: &InvariantCampaignConfig,
) -> InvariantCampaignResult {
    if deployed_bytecode.is_empty() || cfg.selectors.is_empty() || cfg.sequences == 0 {
        return InvariantCampaignResult {
            violated: false,
            invariant_name: None,
            sequences_run: 0,
            txs_executed: 0,
            minimal_trace: Vec::new(),
            summary: "empty bytecode, selectors, or sequence budget".into(),
        };
    }

    let actors = [
        Address::new([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x00,
        ]),
        Address::new([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x01,
        ]),
        Address::new([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x02,
        ]),
    ];

    let mut rng = cfg.seed;
    let mut txs_executed = 0usize;

    let value_samples = [
        U256::ZERO,
        U256::ZERO,
        U256::from(1u64),
        U256::from(100_000_000_000_000_000u128),   // 0.1 ETH
        U256::from(1_000_000_000_000_000_000u128), // 1 ETH
    ];

    for seq_idx in 0..cfg.sequences {
        let step_count = cfg.max_steps.clamp(1, 64);
        let mut trace = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            let actor = actors[(xorshift64(&mut rng) as usize) % actors.len()];
            let sel = cfg.selectors[(xorshift64(&mut rng) as usize) % cfg.selectors.len()];
            let mut calldata = Vec::with_capacity(36);
            calldata.extend_from_slice(&sel);
            let arg_word = (xorshift64(&mut rng) % 4) as u8;
            let mut word = [0u8; 32];
            word[31] = arg_word;
            calldata.extend_from_slice(&word);
            let value_wei = value_samples[(xorshift64(&mut rng) as usize) % value_samples.len()];
            trace.push(InvariantTxStep {
                caller: actor,
                selector: sel,
                value_wei,
                calldata,
            });
        }
        txs_executed += trace.len();

        if let Some(reason) = replay_invariant_sequence(deployed_bytecode, cfg, &trace) {
            // Bounded delta-debugging shrinker: drop unnecessary steps while preserving failure
            let mut shrunk = trace;
            let mut i = 0usize;
            let mut shrink_replays = 0usize;
            while i < shrunk.len() && shrunk.len() > 1 && shrink_replays < 64 {
                let mut cand = shrunk.clone();
                cand.remove(i);
                shrink_replays += 1;
                if replay_invariant_sequence(deployed_bytecode, cfg, &cand).is_some() {
                    shrunk = cand;
                } else {
                    i += 1;
                }
            }
            let inv_name = reason
                .split_whitespace()
                .next()
                .unwrap_or("INVARIANT_BREACH")
                .to_string();
            return InvariantCampaignResult {
                violated: true,
                invariant_name: Some(inv_name),
                sequences_run: seq_idx + 1,
                txs_executed,
                summary: format!(
                    "Invariant violated in {} step(s) (shrunk): {}",
                    shrunk.len(),
                    reason
                ),
                minimal_trace: shrunk,
            };
        }
    }

    InvariantCampaignResult {
        violated: false,
        invariant_name: None,
        sequences_run: cfg.sequences,
        txs_executed,
        minimal_trace: Vec::new(),
        summary: format!(
            "All invariants held across {} sequences ({} txs)",
            cfg.sequences, txs_executed
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revm_stateful_multi_tx_invariant_catches_two_step_unlock_and_shrinks() {
        // Stateful 2-step vulnerable bytecode:
        // - selector 0x11111111 -> SSTORE(slot 1, 1) ("arm")
        // - selector 0x22222222 -> if SLOAD(slot 1) == 1, overwrite protected owner SSTORE(slot 0, 0xdead)
        // Neither transaction alone can violate slot 0; only the 2-tx sequence `arm -> overwrite` does.
        let mut vuln_code: Vec<u8> = vec![
            0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, // selector = CALLDATALOAD(0) >> 224
            0x80, 0x63, 0x11, 0x11, 0x11, 0x11, 0x14, // dup, == 0x11111111
            0x60, 0x1d, 0x57, // JUMPI to arm_pc (0x1d)
            0x63, 0x22, 0x22, 0x22, 0x22, 0x14, // == 0x22222222
            0x60, 0x24, 0x57, // JUMPI to mutate_pc (0x24)
            0x00, 0x00, 0x00, 0x00, // padding to 0x1d
        ];
        debug_assert_eq!(vuln_code.len(), 0x1d);
        vuln_code.extend_from_slice(&[
            0x5b, // 0x1d: JUMPDEST (arm)
            0x60, 0x01, 0x60, 0x01, 0x55, // SSTORE(1, 1)
            0x00, // STOP
        ]);
        debug_assert_eq!(vuln_code.len(), 0x24);
        vuln_code.extend_from_slice(&[
            0x5b, // 0x24: JUMPDEST (mutate)
            0x60, 0x01, 0x54, // SLOAD(1)
            0x60, 0x01, 0x14, // == 1
            0x15, // ISZERO
            0x60, 0x35, 0x57, // JUMPI done
            0x61, 0xde, 0xad, 0x60, 0x00, 0x55, // SSTORE(0, 0xdead)
            0x5b, 0x00, // 0x35: JUMPDEST, STOP
        ]);

        let cfg = InvariantCampaignConfig {
            seed: 42,
            sequences: 32,
            max_steps: 8,
            initial_contract_wei: U256::from(1_000_000_000_000_000_000u128),
            initial_storage: vec![(U256::ZERO, U256::from(0xCAFEu64))],
            protected_slot: Some((U256::ZERO, U256::from(0xCAFEu64))),
            selectors: vec![[0x11, 0x11, 0x11, 0x11], [0x22, 0x22, 0x22, 0x22]],
        };

        let res = run_stateful_revm_invariant_campaign(&vuln_code, &cfg);
        assert!(res.violated, "expected 2-tx violation: {:?}", res);
        assert_eq!(
            res.invariant_name.as_deref(),
            Some("PROTECTED_SLOT_MUTATION")
        );
        assert_eq!(
            res.minimal_trace.len(),
            2,
            "shrinker must reduce failing trace to minimal 2-tx sequence, got: {:?}",
            res.minimal_trace
        );
        assert_eq!(res.minimal_trace[0].selector, [0x11, 0x11, 0x11, 0x11]);
        assert_eq!(res.minimal_trace[1].selector, [0x22, 0x22, 0x22, 0x22]);

        // Hardened contract: always reverts or stops without touching slot 0
        let safe_code = vec![0x00];
        let safe_res = run_stateful_revm_invariant_campaign(&safe_code, &cfg);
        assert!(!safe_res.violated, "hardened contract must hold invariants");
        assert_eq!(safe_res.sequences_run, 32);
    }

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

    #[test]
    fn revm_view_reentrancy_oracle_and_callback_attacker_prove_stale_view() {
        // Minimal EVM victim:
        // - If first byte of calldata == 0xbb (view): return SLOAD(0) (32 bytes)
        // - Else (mutator 0xaa...): CALL(msg.sender, value=1 wei) BEFORE SSTORE(0, 42)
        //   -> During callback, view observes 0; post-tx view observes 42 => PROVEN!
        let mut victim = Vec::new();
        victim.extend_from_slice(&[0x60, 0x00, 0x35, 0x60, 0xf8, 0x1c, 0x60, 0xbb, 0x14]); // byte0 == 0xbb
        let view_jump_idx = victim.len() + 1;
        victim.extend_from_slice(&[0x61, 0x00, 0x00, 0x57]); // PUSH2 view_pc, JUMPI

        // Mutator: CALL(gas=500_000, addr=CALLER, val=1, 0, 0, 0, 0), POP, SSTORE(0, 42), STOP
        victim.extend_from_slice(&[
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret/arg=0
            0x60, 0x01, // value=1 wei
            0x33, // CALLER
            0x62, 0x07, 0xa1, 0x20, 0xf1, 0x50, // CALL(500_000), POP
            0x60, 0x2a, 0x60, 0x00, 0x55, 0x00, // SSTORE(0, 42), STOP
        ]);

        let view_pc = victim.len() as u16;
        victim[view_jump_idx..view_jump_idx + 2].copy_from_slice(&view_pc.to_be_bytes());
        victim.extend_from_slice(&[
            0x5b, // JUMPDEST (view_pc)
            0x60, 0x00, 0x54, // SLOAD(0)
            0x60, 0x00, 0x52, // MSTORE(0)
            0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN(0, 32)
        ]);

        let res = probe_view_reentrancy_in_revm(
            &victim,
            &[0xaa, 0xaa, 0xaa, 0xaa],
            &[0xbb, 0xbb, 0xbb, 0xbb],
        );
        assert!(res.proven, "revm must PROVE view reentrancy: {res:?}");
        assert_eq!(res.profit_wei, U256::from(42));

        // Verify callback-aware attacker builds non-empty valid EVM bytecode for onERC721Received
        let mut magic = [0u8; 32];
        magic[..4].copy_from_slice(&SEL_ON_ERC721_RECEIVED);
        let cb_code = build_callback_reentrant_attacker(
            SEL_ON_ERC721_RECEIVED,
            magic,
            2,
            &[0xaa, 0xaa, 0xaa, 0xaa],
        );
        assert!(cb_code.len() > 60);
    }
}
