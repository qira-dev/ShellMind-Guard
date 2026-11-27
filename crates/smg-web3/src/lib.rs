pub mod context;
pub mod evm_oracle;
pub mod solidity;
pub mod svm_move;
pub mod ultra_web3;

pub use ultra_web3::{
    analyze_move_ultra_depth, analyze_solana_pda_depth, analyze_solidity_ultra_depth,
    detect_diamond_selector_collisions,
};

use context::{EvmSlotEntry, abi_selector, detect_proxy_storage_collisions, ingest_web3_context};
use evm_oracle::{InvariantCampaignConfig, run_stateful_revm_invariant_campaign};
use revm::primitives::U256;
use smg_core::{IndexedFile, Language};
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use solidity::{
    ContractKind, ParsedContract, analyze_solidity_file_with_bases, parse_solidity_file,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use svm_move::{
    analyze_move_file, analyze_solana_rust_file_with_ctx, collect_solana_workspace_context,
    is_solana_rust_source,
};

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Returns `true` only when a repository contains Solidity, Move, Solana/Anchor, or EVM Foundry/Hardhat
/// indicators — guaranteeing zero latency overhead on pure Web2/AppSec repositories.
pub fn repo_has_web3_indicators(project_root: &Path, files: &[IndexedFile]) -> bool {
    if project_root.join("foundry.toml").exists()
        || project_root.join("hardhat.config.js").exists()
        || project_root.join("hardhat.config.ts").exists()
        || project_root.join("Anchor.toml").exists()
        || project_root.join("Move.toml").exists()
    {
        return true;
    }

    for f in files {
        match f.language {
            Language::Solidity | Language::Move => return true,
            Language::Rust => {
                // Fast pre-check before allocating comment-stripped copy on non-Solana Rust repos
                if let Some(text) = read_indexed_text(f)
                    && is_solana_rust_source(&text)
                {
                    let stripped = smg_graph::taint::strip_comments_simple(&text);
                    if is_solana_rust_source(&stripped) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn read_indexed_text(f: &IndexedFile) -> Option<String> {
    if let Some(bytes) = f.cached_bytes.as_deref() {
        return std::str::from_utf8(bytes).ok().map(str::to_string);
    }
    fs::read_to_string(&f.abs_path).ok()
}

/// Scans EVM/Solidity, Solana Rust/Anchor, and Sui/Aptos Move smart contracts inside isolated `smg-web3`.
pub fn scan_web3_repo(
    project_root: &Path,
    files: &[IndexedFile],
    force_web3: bool,
) -> Vec<LocalStaticFinding> {
    scan_web3_repo_with_options(project_root, files, force_web3, false)
}

/// Scans Web3 repositories with optional Phase 16A `--deep-audit` stateful multi-tx `revm`
/// invariant campaigns on compiled Foundry/Hardhat artifacts.
pub fn scan_web3_repo_with_options(
    project_root: &Path,
    files: &[IndexedFile],
    force_web3: bool,
    deep_audit: bool,
) -> Vec<LocalStaticFinding> {
    if !force_web3 && !repo_has_web3_indicators(project_root, files) {
        return Vec::new();
    }

    let ctx = ingest_web3_context(project_root, files);
    let mut all_findings = Vec::new();
    let mut proxies: Vec<(String, String, Vec<EvmSlotEntry>)> = Vec::new();
    let mut impls: Vec<(String, String, Vec<EvmSlotEntry>)> = Vec::new();
    let mut workspace_facet_sigs: Vec<(String, String, usize, String)> = Vec::new();

    // Phase 13B (`P13-03`): Hoist workspace-wide Solidity base contracts for multi-file C3 inheritance
    let mut workspace_sol_bases: HashMap<String, ParsedContract> = HashMap::new();
    for f in files {
        if f.language == Language::Solidity
            && !smg_core::is_test_source_path(&f.rel_path)
            && let Some(text) = read_indexed_text(f)
        {
            for c in parse_solidity_file(&f.rel_path, &text) {
                workspace_sol_bases.insert(c.name.clone(), c);
            }
        }
    }

    // Phase 13B (`P13-04`): Hoist workspace-wide Solana/Anchor `#[derive(Accounts)]` context across split files
    let solana_sources: Vec<(String, String)> = files
        .iter()
        .filter(|f| f.language == Language::Rust && !smg_core::is_test_source_path(&f.rel_path))
        .filter_map(|f| read_indexed_text(f).map(|t| (f.rel_path.clone(), t)))
        .collect();
    let solana_ws_ctx = collect_solana_workspace_context(&solana_sources);

    for f in files {
        let Some(text) = read_indexed_text(f) else {
            continue;
        };
        match f.language {
            Language::Solidity => {
                let (contracts, hits) = analyze_solidity_file_with_bases(
                    &f.rel_path,
                    &text,
                    &ctx,
                    Some(&workspace_sol_bases),
                );
                all_findings.extend(hits);
                if smg_core::is_test_source_path(&f.rel_path) {
                    continue;
                }
                all_findings.extend(ultra_web3::analyze_solidity_ultra_depth(
                    &f.rel_path,
                    &text,
                    &contracts,
                ));
                for c in contracts {
                    if matches!(
                        c.kind,
                        ContractKind::Interface
                            | ContractKind::Library
                            | ContractKind::AbstractContract
                    ) {
                        continue;
                    }
                    if c.name.contains("Facet") {
                        for func in &c.functions {
                            if !func.is_constructor
                                && func.name != "fallback"
                                && func.name != "receive"
                                && matches!(func.visibility.as_str(), "external" | "public")
                            {
                                let sig = ultra_web3::canonical_abi_signature(
                                    &func.name,
                                    &func.params_text,
                                );
                                workspace_facet_sigs.push((
                                    c.name.clone(),
                                    f.rel_path.clone(),
                                    func.start_line,
                                    sig,
                                ));
                            }
                        }
                    }
                    // Phase 16A: Auto-wired `--deep-audit` stateful multi-tx `revm` invariant campaign
                    // (runs on ERC-7201 contracts too — ERC-7201 only exempts slot-0 proxy/impl pairing)
                    if deep_audit
                        && let Some(art) = ctx.lookup_artifact(&f.rel_path, &c.name)
                        && !art.deployed_bytecode.is_empty()
                        && !art.abi_functions.is_empty()
                    {
                        let selectors: Vec<[u8; 4]> = art
                            .abi_functions
                            .iter()
                            .take(12)
                            .map(|sig| abi_selector(sig))
                            .collect();
                        let has_owner_slot0 = c.packed_slots.iter().any(|s| {
                            s.slot == 0
                                && matches!(
                                    s.var_name.to_ascii_lowercase().as_str(),
                                    "owner" | "admin" | "governance" | "guardian"
                                )
                        });
                        let protected_val = U256::from(0xCAFEu64);
                        let inv_cfg = InvariantCampaignConfig {
                            seed: 0x16A0_15D0,
                            sequences: 24,
                            max_steps: 6,
                            initial_contract_wei: U256::from(1_000_000_000_000_000_000u128),
                            initial_storage: if has_owner_slot0 {
                                vec![(U256::ZERO, protected_val)]
                            } else {
                                Vec::new()
                            },
                            protected_slot: has_owner_slot0.then_some((U256::ZERO, protected_val)),
                            selectors,
                        };
                        let inv_res =
                            run_stateful_revm_invariant_campaign(&art.deployed_bytecode, &inv_cfg);
                        if inv_res.violated {
                            let is_solvency =
                                inv_res.invariant_name.as_deref() == Some("SOLVENCY_BREACH");
                            all_findings.push(LocalStaticFinding {
                                rule_id: if is_solvency {
                                    "SMG-WEB3-REENTRANCY".into()
                                } else {
                                    "SMG-WEB3-ACCESS".into()
                                },
                                severity: "CRITICAL".into(),
                                title: format!(
                                    "[revm {} multi-tx invariant] `{}` violated {}",
                                    if is_solvency { "HEURISTIC" } else { "PROVEN" },
                                    c.name,
                                    inv_res.summary
                                ),
                                rel_path: f.rel_path.clone(),
                                line: c.start_line.max(1),
                                symbol: c.name.clone(),
                                sink_kind: if is_solvency {
                                    SinkKind::BalanceUpdate
                                } else {
                                    SinkKind::AuthMutation
                                },
                                missing_guard: GuardKind::Auth,
                                confidence: if is_solvency {
                                    Confidence::Heuristic
                                } else {
                                    Confidence::Proven
                                },
                                remediation: "Enforce caller authorization and protocol solvency invariants across all multi-transaction call sequences.".into(),
                            });
                        }
                        // Phase 29A: Auto-wired read-only/view reentrancy probe on contracts exposing
                        // both mutating external calls and view price/share getters (bounded to 4 pairs).
                        let view_getters: Vec<(&String, [u8; 4])> = art
                            .abi_functions
                            .iter()
                            .filter(|sig| {
                                let low = sig.to_ascii_lowercase();
                                low.starts_with("getprice(")
                                    || low.starts_with("pricepershare(")
                                    || low.starts_with("getvirtualprice(")
                                    || low.starts_with("exchangerate(")
                                    || low.starts_with("totalassets(")
                            })
                            .take(2)
                            .map(|sig| (sig, abi_selector(sig)))
                            .collect();
                        if !view_getters.is_empty() {
                            let mutators: Vec<(&String, [u8; 4])> = art
                                .abi_functions
                                .iter()
                                .filter(|sig| {
                                    let low = sig.to_ascii_lowercase();
                                    low.starts_with("withdraw(")
                                        || low.starts_with("redeem(")
                                        || low.starts_with("remove_liquidity(")
                                        || low.starts_with("claim(")
                                })
                                .take(2)
                                .map(|sig| (sig, abi_selector(sig)))
                                .collect();
                            'view_probe: for (msig, msel) in &mutators {
                                for (vsig, vsel) in &view_getters {
                                    let vr = evm_oracle::probe_view_reentrancy_in_revm(
                                        &art.deployed_bytecode,
                                        msel,
                                        vsel,
                                    );
                                    if vr.proven {
                                        all_findings.push(LocalStaticFinding {
                                            rule_id: "SMG-WEB3-REENTRANCY".into(),
                                            severity: "CRITICAL".into(),
                                            title: format!(
                                                "[revm PROVEN read-only reentrancy] `{}` view `{vsig}` returned stale value during `{msig}` callback ({})",
                                                c.name, vr.summary
                                            ),
                                            rel_path: f.rel_path.clone(),
                                            line: c.start_line.max(1),
                                            symbol: c.name.clone(),
                                            sink_kind: SinkKind::BalanceUpdate,
                                            missing_guard: GuardKind::TxLock,
                                            confidence: Confidence::Proven,
                                            remediation: "Apply nonReentrant guards to view price/share getters or update all accounting state before external calls.".into(),
                                        });
                                        break 'view_probe;
                                    }
                                }
                            }
                        }
                    }
                    if c.has_erc7201_namespace {
                        continue;
                    }
                    // Prefer compiler `storageLayout` from Foundry/Hardhat when present
                    let slots = ctx
                        .lookup_artifact(&f.rel_path, &c.name)
                        .filter(|a| !a.storage_slots.is_empty())
                        .map(|a| a.storage_slots.clone())
                        .unwrap_or(c.packed_slots);
                    if slots.is_empty() {
                        continue;
                    }
                    if c.is_proxy_like {
                        proxies.push((c.name, f.rel_path.clone(), slots));
                    } else {
                        impls.push((c.name, f.rel_path.clone(), slots));
                    }
                }
            }
            Language::Move => {
                all_findings.extend(analyze_move_file(&f.rel_path, &text));
                if !smg_core::is_test_source_path(&f.rel_path) {
                    all_findings.extend(ultra_web3::analyze_move_ultra_depth(&f.rel_path, &text));
                }
            }
            Language::Rust => {
                all_findings.extend(analyze_solana_rust_file_with_ctx(
                    &f.rel_path,
                    &text,
                    Some(&solana_ws_ctx),
                ));
                if !smg_core::is_test_source_path(&f.rel_path) {
                    all_findings.extend(ultra_web3::analyze_solana_pda_depth_with_ctx(
                        &f.rel_path,
                        &text,
                        Some(&solana_ws_ctx),
                    ));
                }
            }
            _ => {}
        }
    }

    if !workspace_facet_sigs.is_empty() {
        all_findings.extend(detect_diamond_selector_collisions(&workspace_facet_sigs));
    }
    all_findings.extend(detect_proxy_storage_collisions(&proxies, &impls));

    // Deterministic deduplication by canonical defect family `(family, rel_path, line)` so
    // umbrella (`SMG-WEB3-*`) and deep (`SMG-SOL-*` / `SMG-MOVE-*`) rules never double-fire on one line.
    fn web3_dedup_family(f: &LocalStaticFinding) -> &str {
        match f.rule_id.as_str() {
            "SMG-SOL-ARBITRARY-CPI" => "SOL_CPI",
            "SMG-WEB3-SOLANA" if f.title.starts_with("Arbitrary CPI target") => "SOL_CPI",
            "SMG-SOL-PDA-NONCANONICAL" => "SOL_PDA",
            "SMG-WEB3-SOLANA" if f.title.starts_with("Non-canonical PDA") => "SOL_PDA",
            "SMG-MOVE-ABILITY-LEAK" => "MOVE_ABILITY",
            "SMG-WEB3-MOVE"
                if f.title.contains("declares `drop`/`copy`")
                    || f.title.contains("declares `copy`/`store`") =>
            {
                "MOVE_ABILITY"
            }
            "SMG-MOVE-ENTRY-NO-AUTH" => "MOVE_ENTRY_AUTH",
            "SMG-WEB3-MOVE" if f.title.starts_with("Unprotected Move privileged function") => {
                "MOVE_ENTRY_AUTH"
            }
            other => other,
        }
    }
    fn family_rule_pref(family: &str, rule_id: &str) -> u8 {
        match (family, rule_id) {
            ("SOL_CPI", "SMG-SOL-ARBITRARY-CPI") => 2,
            ("SOL_PDA", "SMG-SOL-PDA-NONCANONICAL") => 2,
            ("MOVE_ABILITY" | "MOVE_ENTRY_AUTH", "SMG-WEB3-MOVE") => 2,
            _ => 1,
        }
    }
    let conf_rank = |c: Confidence| -> u8 {
        match c {
            Confidence::Proven => 3,
            Confidence::Confirmed => 2,
            Confidence::Heuristic => 1,
        }
    };
    let mut best_by_key: HashMap<(String, String, usize), usize> = HashMap::new();
    let mut deduped: Vec<LocalStaticFinding> = Vec::new();
    for mut f in all_findings {
        f.rel_path = smg_core::normalize_rel_path_posix_nfc(&f.rel_path);
        let family = web3_dedup_family(&f).to_string();
        let key = (family.clone(), f.rel_path.clone(), f.line);
        if let Some(&idx) = best_by_key.get(&key) {
            let new_key = (
                severity_rank(&f.severity),
                conf_rank(f.confidence),
                family_rule_pref(&family, &f.rule_id),
            );
            let old_key = (
                severity_rank(&deduped[idx].severity),
                conf_rank(deduped[idx].confidence),
                family_rule_pref(&family, &deduped[idx].rule_id),
            );
            if new_key > old_key {
                deduped[idx] = f;
            }
        } else {
            best_by_key.insert(key, deduped.len());
            deduped.push(f);
        }
    }
    deduped.sort_by(|a, b| {
        a.rel_path
            .cmp(&b.rel_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.title.cmp(&b.title))
    });
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mem_indexed(rel: &str, lang: Language, src: &str) -> IndexedFile {
        IndexedFile {
            rel_path: rel.into(),
            abs_path: Path::new(rel).to_path_buf(),
            language: lang,
            blake3_hash: "0".into(),
            mtime_ns: 0,
            size_bytes: src.len() as u64,
            cached_bytes: Some(src.as_bytes().to_vec()),
        }
    }

    #[test]
    fn non_web3_web2_repo_returns_zero_latency_and_findings() {
        let dir = Path::new("/tmp");
        let files = vec![
            mem_indexed("src/app.ts", Language::TypeScript, "export const x = 1;\n"),
            mem_indexed(
                "src/lib.rs",
                Language::Rust,
                "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
            ),
        ];
        assert!(!repo_has_web3_indicators(dir, &files));
        assert!(scan_web3_repo(dir, &files, false).is_empty());
    }

    #[test]
    fn web3_positive_and_hardened_negative_matrix_across_evm_solana_and_move() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_web3_matrix_{nanos}"));
        fs::create_dir_all(root.join("out")).unwrap();

        let vuln_vault_bytecode_hex = "0x3415600a5734600055005b6000548015602a57600060006000600084336207a120f150506000600055005b5000";
        fs::write(
            root.join("out/VulnVault.json"),
            format!(
                r#"{{
  "contractName": "VulnVault",
  "abi": [
    {{"type": "function", "name": "deposit", "inputs": []}},
    {{"type": "function", "name": "withdraw", "inputs": []}}
  ],
  "deployedBytecode": {{ "object": "{vuln_vault_bytecode_hex}" }}
}}"#
            ),
        )
        .unwrap();

        let vuln_sol = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BadProxy {
    address public implementation;
    fallback() external payable {
        address impl = implementation;
        assembly { delegatecall(gas(), impl, 0, calldatasize(), 0, 0) }
    }
}

contract VulnVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function getSharePrice() external view returns (uint256) {
        return (totalAssets * 1e18) / totalSupply;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return (assets * totalSupply) / totalAssets;
    }

    function feeMath(uint256 amount, uint256 denom, uint256 bps) external pure returns (uint256) {
        return (amount / denom) * bps;
    }

    function claimSig(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad");
        owner = msg.sender;
    }

    function borrowPrice(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IPair(pair).getReserves();
        return uint256(r0) * 1e18 / uint256(r1);
    }
}
"#;

        let safe_sol = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuardSafe {
    uint256 private _locked;
    modifier nonReentrant() {
        require(_locked == 0, "reentrant");
        _locked = 1;
        _;
        _locked = 0;
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }
    address public owner;
}

contract HardenedVault is ReentrancyGuardSafe {
    /// @custom:storage-location erc7201:shellmind.vault.storage
    struct VaultStorage {
        mapping(address => uint256) balances;
    }
    mapping(address => uint256) public balances;
    mapping(uint256 => bool) public usedNonces;

    function initialize(address newOwner) external onlyOwner {
        require(owner == address(0), "init");
        owner = newOwner;
    }

    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
    }

    function convertToShares(uint256 assets) external pure returns (uint256) {
        return Math.mulDiv(assets, 1 + 10 ** 3, 1 + 1, Math.Rounding.Floor);
    }

    function claimVerified(bytes32 digest, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedNonces[nonce], "used");
        usedNonces[nonce] = true;
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner && block.chainid > 0);
    }

    function oraclePrice(address feed) external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        require(price > 0 && block.timestamp - updatedAt <= 3600, "stale");
        return uint256(price);
    }
}
"#;

        let vuln_anchor = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UnsafeWithdraw<'info> {
    pub authority: AccountInfo<'info>,
    pub vault: UncheckedAccount<'info>,
    pub token_program: AccountInfo<'info>,
}

pub fn cpi_exec(ctx: Context<UnsafeWithdraw>) -> ProgramResult {
    solana_program::program::invoke(&ix, &[ctx.accounts.token_program.clone()])
}
"#;

        let safe_anchor = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SafeWithdraw<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultState>,
    pub token_program: Program<'info, Token>,
}
"#;

        let vuln_move = r#"
module vault::core {
    public entry fun init(ctx: &mut TxContext) {
        transfer::share_object(Vault {});
    }
    public entry fun admin_withdraw(vault: &mut Vault, ctx: &mut TxContext) {
        coin::split(&mut vault.coin, 10, ctx);
    }
}
"#;

        let safe_move = r#"
module vault::safe_core {
    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap {}, tx_context::sender(ctx));
    }
    public entry fun admin_withdraw(_cap: &AdminCap, vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        assert!(amount > 0, 1);
        coin::split(&mut vault.coin, amount, ctx);
    }
}
"#;

        let files = vec![
            mem_indexed("contracts/VulnVault.sol", Language::Solidity, vuln_sol),
            mem_indexed("contracts/HardenedVault.sol", Language::Solidity, safe_sol),
            mem_indexed("programs/vuln.rs", Language::Rust, vuln_anchor),
            mem_indexed("programs/safe.rs", Language::Rust, safe_anchor),
            mem_indexed("sources/vuln.move", Language::Move, vuln_move),
            mem_indexed("sources/safe.move", Language::Move, safe_move),
            mem_indexed("test/VulnTest.t.sol", Language::Solidity, vuln_sol),
        ];

        let hits = scan_web3_repo(&root, &files, false);
        let vuln_rules: Vec<&str> = hits
            .iter()
            .filter(|h| !h.rel_path.contains("Hardened") && !h.rel_path.contains("safe"))
            .map(|h| h.rule_id.as_str())
            .collect();

        assert!(vuln_rules.contains(&"SMG-WEB3-REENTRANCY"), "{hits:?}");
        assert!(
            hits.iter().any(|h| {
                h.rule_id == "SMG-WEB3-REENTRANCY"
                    && matches!(h.confidence, smg_graph::Confidence::Proven)
            }),
            "expected compiled Foundry bytecode reentrancy to upgrade to PROVEN via revm: {hits:#?}"
        );
        assert!(vuln_rules.contains(&"SMG-WEB3-STORAGE"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-ROUNDING"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-REPLAY"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-ACCESS"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-SOLANA"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-MOVE"), "{hits:?}");
        assert!(vuln_rules.contains(&"SMG-WEB3-ORACLE"), "{hits:?}");

        let safe_hits: Vec<&LocalStaticFinding> = hits
            .iter()
            .filter(|h| {
                h.rel_path.contains("Hardened")
                    || h.rel_path.contains("safe")
                    || h.rel_path.ends_with(".t.sol")
            })
            .collect();
        assert!(
            safe_hits.is_empty(),
            "hardened & test files produced FPs: {safe_hits:#?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn web3_audit_counterexamples_zero_false_positives_and_strict_detection() {
        let dir = Path::new("/tmp");

        // 1. Benign counterexamples that MUST produce 0 false positives:
        // - Mutually exclusive if/else call vs state write
        // - Early-return call branch before state write
        // - Inherited custom auth/lock modifiers from base contract
        // - Anchor `#[account(has_one=authority)]` without space + CPI with `Program<'info, Token>` in `Context<SafeCpi>`
        // - Move `coin::split` guarded by `>= 1` and helper `public fun init(val: u64)` without `TxContext`
        let benign_sol = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract BaseGuards {
    address public gov;
    uint256 private _entered;
    modifier checkGov() {
        require(msg.sender == gov, "not gov");
        _;
    }
    modifier guardEntered() {
        require(_entered == 0, "busy");
        _entered = 1;
        _;
        _entered = 0;
    }
}

contract SafePatterns is BaseGuards {
    mapping(address => uint256) public balances;

    function setAdmin(address nextGov) external checkGov {
        gov = nextGov;
    }

    function branchDisjoint(bool payDirect, uint256 amt) external {
        if (payDirect) {
            (bool ok, ) = msg.sender.call{value: amt}("");
            require(ok);
        } else {
            balances[msg.sender] = 0;
        }
    }

    function guardedByInheritedLock(uint256 amt) external guardEntered {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#;
        let benign_anchor = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SafeCpi<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one=authority)]
    pub vault: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

pub fn run_safe_cpi(ctx: Context<SafeCpi>) -> ProgramResult {
    solana_program::program::invoke(&ix, &[ctx.accounts.token_program.to_account_info()])
}
"#;
        let benign_move = r#"
module vault::benign_move {
    public fun init(default_val: u64): u64 {
        default_val
    }
    public entry fun admin_set(_cap: &AdminCap, amount: u64, ctx: &mut TxContext) {
        assert!(amount >= 1, 0);
        coin::split(&mut coin_obj, amount, ctx);
    }
}
"#;
        let benign_files = vec![
            mem_indexed("contracts/SafePatterns.sol", Language::Solidity, benign_sol),
            mem_indexed("programs/benign.rs", Language::Rust, benign_anchor),
            mem_indexed("sources/benign.move", Language::Move, benign_move),
        ];
        let benign_hits = scan_web3_repo(dir, &benign_files, true);
        assert!(
            benign_hits.is_empty(),
            "Audited benign Web3 counterexamples must produce 0 false positives, got: {benign_hits:#?}"
        );

        // 2. Subtle true-positive counterexamples that MUST be caught:
        // - Commented-out `// require(msg.sender == owner);` and dead `address s = msg.sender;` in `setOwner`
        // - Same-line CEI violation `(bool ok,) = msg.sender.call{value: b}(""); balances[msg.sender] = 0;`
        // - Intra-contract internal helper call `_sendEth(b)` before `balances[msg.sender] = 0;`
        // - Move `set_capacity(vault: &mut Vault, capacity: u64)` where parameter name contains "cap" but type is `u64`
        // - Solana file with both a safe instruction checking `authority.is_signer` and an unsafe `UncheckedAccount` struct
        let subtle_sol = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SubtleVuln {
    address public owner;
    mapping(address => uint256) public balances;

    function setOwner(address newOwner) external {
        // require(msg.sender == owner);
        address caller = msg.sender;
        owner = newOwner;
    }

    function sameLineWithdraw(uint256 b) external {
        (bool ok, ) = msg.sender.call{value: b}(""); balances[msg.sender] = 0;
    }

    function _doSend(uint256 b) internal {
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok);
    }

    function helperWithdraw(uint256 b) external {
        _doSend(b);
        balances[msg.sender] = 0;
    }
}
"#;
        let subtle_anchor = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CheckedCtx<'info> {
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UncheckedCtx<'info> {
    pub authority: AccountInfo<'info>,
}

pub fn checked_ix(ctx: Context<CheckedCtx>) -> ProgramResult {
    if !ctx.accounts.authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    Ok(())
}

pub fn unchecked_ix(_ctx: Context<UncheckedCtx>) -> ProgramResult {
    Ok(())
}
"#;
        let subtle_move = r#"
module vault::subtle_move {
    public entry fun set_capacity(capacity: u64) {
        let _ = capacity;
    }
}
"#;
        let subtle_files = vec![
            mem_indexed("contracts/SubtleVuln.sol", Language::Solidity, subtle_sol),
            mem_indexed("programs/subtle.rs", Language::Rust, subtle_anchor),
            mem_indexed("sources/subtle.move", Language::Move, subtle_move),
        ];
        let subtle_hits = scan_web3_repo(dir, &subtle_files, true);

        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-ACCESS" && h.symbol == "SubtleVuln.setOwner"),
            "Must catch setOwner with commented-out msg.sender and dead caller = msg.sender: {subtle_hits:#?}"
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-REENTRANCY"
                    && h.symbol == "SubtleVuln.sameLineWithdraw"),
            "Must catch same-line CEI reentrancy: {subtle_hits:#?}"
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-REENTRANCY"
                    && h.symbol == "SubtleVuln.helperWithdraw"),
            "Must catch internal helper CEI reentrancy: {subtle_hits:#?}"
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-SOLANA" && h.symbol == "UncheckedCtx.authority"),
            "Must catch UncheckedCtx.authority even when CheckedCtx.authority is verified in another instruction: {subtle_hits:#?}"
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-MOVE" && h.symbol == "set_capacity"),
            "Must catch Move set_capacity(capacity: u64) without capability type: {subtle_hits:#?}"
        );
    }

    #[test]
    fn test_sprint6_p13_03_and_p13_04_multifile_c3_lib_linking_solana_split_and_move_abilities() {
        let mk_file = |rel: &str, lang: Language, src: &str| IndexedFile {
            rel_path: rel.into(),
            abs_path: Path::new(rel).to_path_buf(),
            language: lang,
            blake3_hash: "0".into(),
            mtime_ns: 0,
            size_bytes: src.len() as u64,
            cached_bytes: Some(src.as_bytes().to_vec()),
        };
        // 1. Solidity library placeholder linking (`__$34-hex$__`)
        let linked =
            context::decode_hex_bytecode("0x6000__$1234567890abcdef1234567890abcdef12$__00");
        assert_eq!(linked.len(), 23);
        assert_eq!(&linked[..2], &[0x60, 0x00]);
        assert_eq!(linked[22], 0x00);

        // 2. Multi-file C3 inheritance (Ownable in BaseOwnable.sol -> Treasury.sol uses custom `onlyAdmin`) -> 0 FP
        let base_ownable = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
abstract contract BaseOwnable {
    address public owner;
    modifier onlyAdmin() {
        require(msg.sender == owner, "not admin");
        _;
    }
}
"#;
        let treasury = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Treasury is BaseOwnable {
    function setFeeRecipient(address next) external onlyAdmin {
        owner = next;
    }
}
"#;
        // 3. Split Solana Anchor workspace (`state.rs` + `instructions.rs`) -> 0 FP
        let sol_state = r#"
use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct WithdrawAccounts<'info> {
    pub authority: AccountInfo<'info>,
}
"#;
        let sol_ix = r#"
use anchor_lang::prelude::*;
pub fn withdraw(ctx: Context<WithdrawAccounts>) -> Result<()> {
    require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
    Ok(())
}
"#;
        let safe_files = vec![
            mk_file(
                "contracts/BaseOwnable.sol",
                Language::Solidity,
                base_ownable,
            ),
            mk_file("contracts/Treasury.sol", Language::Solidity, treasury),
            mk_file("programs/vault/src/state.rs", Language::Rust, sol_state),
            mk_file("programs/vault/src/instructions.rs", Language::Rust, sol_ix),
        ];
        let safe_hits = scan_web3_repo(Path::new("/nonexistent"), &safe_files, true);
        assert!(
            safe_hits.is_empty(),
            "Cross-file Ownable & split Anchor workspace must produce 0 FPs, got: {safe_hits:#?}"
        );

        // 4. Move `struct has <abilities>`: hot-potato `drop` + `*Cap` `store` caught, safe structs spared
        let move_src = r#"
module defi::pool {
    public struct FlashLoanReceipt has drop { amount: u64 }
    public struct AdminCap has key, store { id: u64 }
    public struct SafeCap has key { id: u64 }
    public struct SafeReceipt { amount: u64 }
}
"#;
        let move_hits = scan_web3_repo(
            Path::new("/nonexistent"),
            &[mk_file("sources/pool.move", Language::Move, move_src)],
            true,
        );
        assert!(
            move_hits.iter().any(|h| h.rule_id == "SMG-WEB3-MOVE"
                && h.symbol == "FlashLoanReceipt"
                && h.severity == "CRITICAL"),
            "Must catch hot-potato drop ability: {move_hits:#?}"
        );
        assert!(
            move_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-MOVE" && h.symbol == "AdminCap"),
            "Must catch AdminCap store ability: {move_hits:#?}"
        );
        assert!(
            !move_hits
                .iter()
                .any(|h| h.symbol == "SafeCap" || h.symbol == "SafeReceipt"),
            "Safe Move structs must not be flagged: {move_hits:#?}"
        );
    }

    #[test]
    fn test_wormhole_solana_cpi_and_sui_move_no_double_fire() {
        let dir = std::env::temp_dir();
        let mk_mem_file = |rel: &str, lang: Language, code: &str| IndexedFile {
            abs_path: std::path::PathBuf::from(rel),
            rel_path: rel.to_string(),
            language: lang,
            size_bytes: code.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(code.as_bytes().to_vec()),
        };

        // 1. Unvalidated invoke_signed must emit EXACTLY 1 finding (SMG-SOL-ARBITRARY-CPI), NOT 2
        let sol_cpi = r#"
use anchor_lang::prelude::*;
use solana_program::program::invoke_signed;

#[derive(Accounts)]
pub struct SafePda<'info> {
    #[account(seeds = [b"emitter"], bump)]
    pub emitter_authority: UncheckedAccount<'info>,
}

pub fn relay(ix: &solana_program::instruction::Instruction, accs: &[AccountInfo]) -> ProgramResult {
    invoke_signed(ix, accs, &[])
}
"#;
        let sol_file = mk_mem_file("svm/post_message/src/lib.rs", Language::Rust, sol_cpi);
        let sol_hits = scan_web3_repo(&dir, &[sol_file], true);
        let cpi_hits: Vec<_> = sol_hits
            .iter()
            .filter(|h| {
                h.rule_id == "SMG-SOL-ARBITRARY-CPI" || h.title.starts_with("Arbitrary CPI target")
            })
            .collect();
        assert_eq!(
            cpi_hits.len(),
            1,
            "Unvalidated invoke_signed must not double-fire: {cpi_hits:#?}"
        );
        assert_eq!(cpi_hits[0].rule_id, "SMG-SOL-ARBITRARY-CPI");
        assert!(
            !sol_hits
                .iter()
                .any(|h| h.symbol.contains("emitter_authority")),
            "Anchor PDA #[account(seeds = ...)] must not be flagged as missing Signer: {sol_hits:#?}"
        );

        // 2. Sui Move public(package) & `FeeCollector has store` => 0 findings; unprotected public entry => 1 finding
        let move_src = r#"
module wormhole::fee_collector {
    public struct FeeCollector has store {
        balance: u64,
    }

    public(package) fun withdraw_fee(fc: &mut FeeCollector): u64 {
        fc.balance
    }

    public entry fun withdraw_all(vault: &mut FeeCollector) {
        vault.balance = 0;
    }
}
"#;
        let move_file = mk_mem_file(
            "sui/wormhole/sources/fee_collector.move",
            Language::Move,
            move_src,
        );
        let move_hits = scan_web3_repo(&dir, &[move_file], true);
        assert!(
            !move_hits
                .iter()
                .any(|h| h.title.contains("FeeCollector") || h.title.contains("withdraw_fee")),
            "Internal public(package) and `has store` resource must not fire: {move_hits:#?}"
        );
        let entry_hits: Vec<_> = move_hits
            .iter()
            .filter(|h| h.rule_id == "SMG-WEB3-MOVE" || h.rule_id == "SMG-MOVE-ENTRY-NO-AUTH")
            .collect();
        assert_eq!(
            entry_hits.len(),
            1,
            "Unprotected Move entry must emit exactly 1 deduplicated finding: {entry_hits:#?}"
        );
    }
}
