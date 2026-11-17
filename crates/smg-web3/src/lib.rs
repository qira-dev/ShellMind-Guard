pub mod context;
pub mod evm_oracle;
pub mod solidity;
pub mod svm_move;

use context::{EvmSlotEntry, detect_proxy_storage_collisions, ingest_web3_context};
use smg_core::{IndexedFile, Language};
use smg_graph::LocalStaticFinding;
use solidity::{ContractKind, analyze_solidity_file};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use svm_move::{analyze_move_file, analyze_solana_rust_file, is_solana_rust_source};

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
                if let Some(text) = read_indexed_text(f)
                    && is_solana_rust_source(&text)
                {
                    return true;
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
    if !force_web3 && !repo_has_web3_indicators(project_root, files) {
        return Vec::new();
    }

    let ctx = ingest_web3_context(project_root, files);
    let mut all_findings = Vec::new();
    let mut proxies: Vec<(String, String, Vec<EvmSlotEntry>)> = Vec::new();
    let mut impls: Vec<(String, String, Vec<EvmSlotEntry>)> = Vec::new();

    for f in files {
        let Some(text) = read_indexed_text(f) else {
            continue;
        };
        match f.language {
            Language::Solidity => {
                let (contracts, hits) = analyze_solidity_file(&f.rel_path, &text, &ctx);
                all_findings.extend(hits);
                if smg_core::is_test_source_path(&f.rel_path) {
                    continue;
                }
                for c in contracts {
                    if matches!(
                        c.kind,
                        ContractKind::Interface
                            | ContractKind::Library
                            | ContractKind::AbstractContract
                    ) || c.has_erc7201_namespace
                    {
                        continue;
                    }
                    // Prefer compiler `storageLayout` from Foundry/Hardhat when present
                    let slots = ctx
                        .artifacts
                        .get(&c.name)
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
            }
            Language::Rust => {
                all_findings.extend(analyze_solana_rust_file(&f.rel_path, &text));
            }
            _ => {}
        }
    }

    all_findings.extend(detect_proxy_storage_collisions(&proxies, &impls));

    // Deterministic deduplication by (rule_id, rel_path, line)
    let mut seen: HashSet<(String, String, usize)> = HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.rel_path.clone(), f.line)));
    all_findings
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

        // Real vulnerable vault compiled runtime bytecode supporting:
        // - deposit() when CALLVALUE > 0: SSTORE(0, CALLVALUE)
        // - withdraw() when CALLVALUE == 0: SLOAD(0) -> CALL caller -> SSTORE(0, 0) (CEI violation)
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
}
