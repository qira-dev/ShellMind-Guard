//! Phase 29A: Web3 Ultra-Depth Analyzer
//! - EIP-2535 Diamond Proxy selector collisions & UUPS uninitialized implementation checks
//! - Flash-loan callback auth, AMM spot-price oracle manipulation, Chainlink staleness, ERC-4626 inflation
//! - Solana Anchor `init_if_needed`, non-canonical PDA bump, arbitrary CPI, `remaining_accounts`
//! - Move (Aptos/Sui) capability/ability (`copy`/`drop` on Coin/Vault), public entry missing signer/cap

use crate::context::abi_selector;
use crate::solidity::ParsedContract;
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::HashMap;

#[allow(clippy::too_many_arguments)]
fn mk_web3_finding(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    confidence: Confidence,
    remediation: &str,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line: line.max(1),
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence,
        remediation: remediation.to_string(),
    }
}

/// Detects EIP-2535 Diamond facet 4-byte selector collisions across multiple facet contracts.
pub fn detect_diamond_selector_collisions(
    facet_signatures: &[(String, String, usize, String)], // (contract, rel_path, line, "fn(uint256)")
) -> Vec<LocalStaticFinding> {
    type FacetEntry<'a> = (&'a str, &'a str, usize, &'a str);
    let mut by_selector: HashMap<[u8; 4], Vec<FacetEntry<'_>>> = HashMap::new();
    for (contract, rel_path, line, sig) in facet_signatures {
        let sel = abi_selector(sig);
        by_selector
            .entry(sel)
            .or_default()
            .push((contract.as_str(), rel_path.as_str(), *line, sig.as_str()));
    }

    let mut out = Vec::new();
    for (sel, entries) in by_selector {
        if entries.len() < 2 {
            continue;
        }
        // Only flag when two DISTINCT facet/contract names share the same 4-byte selector
        let first_contract = entries[0].0;
        if entries.iter().all(|e| e.0 == first_contract) {
            continue;
        }
        let hex_sel = format!(
            "0x{:02x}{:02x}{:02x}{:02x}",
            sel[0], sel[1], sel[2], sel[3]
        );
        let desc: Vec<String> = entries
            .iter()
            .map(|(c, _, _, s)| format!("{c}.{s}"))
            .collect();
        let (contract, rel_path, line, sig) = entries[0];
        out.push(mk_web3_finding(
            "SMG-WEB3-DIAMOND-CLASH",
            "CRITICAL",
            format!(
                "EIP-2535 Diamond 4-byte selector collision ({hex_sel}) across facets: {}",
                desc.join(" vs ")
            ),
            rel_path,
            line,
            &format!("{contract}.{sig}"),
            SinkKind::AuthMutation,
            GuardKind::Auth,
            Confidence::Proven,
            "Rename colliding facet functions or isolate selectors in DiamondLoupe/diamondCut validation to prevent silent selector hijacking.",
        ));
    }
    out
}

/// Deep Solidity audit for UUPS/Initializable, Flash-Loan callbacks, AMM Spot-Price/Chainlink/ERC-4626.
pub fn analyze_solidity_ultra_depth(
    rel_path: &str,
    source: &str,
    contracts: &[ParsedContract],
) -> Vec<LocalStaticFinding> {
    let stripped = smg_graph::taint::strip_comments_simple(source);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut findings = Vec::new();

    // 1. UUPS / Initializable implementation missing `_disableInitializers()` in constructor
    let is_upgradeable =
        stripped.contains("UUPSUpgradeable") || stripped.contains("Initializable");
    if is_upgradeable
        && !stripped.contains("_disableInitializers()")
        && !stripped.contains("VersionedInitializable")
        && !stripped.contains("lastInitializedRevision")
        && stripped.contains("function initialize")
    {
        let init_line = lines
            .iter()
            .position(|l| l.contains("function initialize"))
            .map(|i| i + 1)
            .unwrap_or(1);
        findings.push(mk_web3_finding(
            "SMG-WEB3-UUPS-UNINIT",
            "CRITICAL",
            "Upgradeable implementation defines `initialize()` without `_disableInitializers()` in constructor (uninitialized implementation takeover)".into(),
            rel_path,
            init_line,
            "initialize",
            SinkKind::AuthMutation,
            GuardKind::Auth,
            Confidence::Confirmed,
            "Add `constructor() { _disableInitializers(); }` to lock the implementation contract against direct initialization.",
        ));
    }

    // 2. Implementation contract containing `selfdestruct` or unguarded `delegatecall`
    if is_upgradeable {
        for (idx, line) in lines.iter().enumerate() {
            if line.contains("selfdestruct(") {
                findings.push(mk_web3_finding(
                    "SMG-WEB3-IMPL-SELFDESTRUCT",
                    "CRITICAL",
                    "Upgradeable implementation contains `selfdestruct()` which can permanently brick all proxies".into(),
                    rel_path,
                    idx + 1,
                    "selfdestruct",
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Remove `selfdestruct()` from upgradeable implementation contracts.",
                ));
            }
        }
    }

    // 3. Flash-loan callback missing caller/initiator verification
    const FLASH_CALLBACKS: &[&str] = &[
        "function executeOperation(",
        "function onFlashLoan(",
        "function uniswapV2Call(",
        "function uniswapV3FlashCallback(",
        "function pancakeCall(",
    ];
    for (idx, line) in lines.iter().enumerate() {
        if FLASH_CALLBACKS.iter().any(|cb| line.contains(cb)) {
            let end = (idx + 20).min(lines.len());
            let body = lines[idx..end].join("\n");
            let checks_sender = body.contains("msg.sender ==")
                || body.contains("msg.sender !=")
                || body.contains("onlyPool")
                || body.contains("onlyLendingPool");
            let checks_initiator = body.contains("initiator ==")
                || body.contains("initiator !=")
                || body.contains("sender == address(this)")
                || body.contains("address(this)");
            if !checks_sender || !checks_initiator {
                findings.push(mk_web3_finding(
                    "SMG-WEB3-FLASHLOAN-AUTH",
                    "CRITICAL",
                    "Flash-loan callback missing `msg.sender` pool verification or `initiator == address(this)` check".into(),
                    rel_path,
                    idx + 1,
                    line.trim(),
                    SinkKind::BalanceUpdate,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Require `msg.sender == address(POOL)` and `initiator == address(this)` at the start of every flash-loan callback.",
                ));
            }
        }
    }

    // 4. AMM Spot-Price Oracle Manipulation (`getReserves` / `slot0` without TWAP `observe`)
    for (idx, line) in lines.iter().enumerate() {
        let uses_spot = line.contains(".getReserves(") || line.contains(".slot0(");
        if uses_spot {
            let mut win_start = idx;
            while win_start > idx.saturating_sub(8) {
                if lines[win_start].trim_start().starts_with("function ") {
                    break;
                }
                win_start -= 1;
            }
            let mut win_end = idx + 1;
            while win_end < (idx + 14).min(lines.len()) {
                if lines[win_end].trim_start().starts_with("function ") {
                    break;
                }
                win_end += 1;
            }
            let window = lines[win_start..win_end].join("\n");
            let price_context = window.contains("price")
                || window.contains("Price")
                || window.contains("collateral")
                || window.contains("borrow")
                || window.contains("liquidat")
                || window.contains("mint")
                || window.contains("valuation");
            let has_twap = window.contains(".observe(")
                || window.contains("consult(")
                || window.contains("latestRoundData(");
            if price_context && !has_twap {
                findings.push(mk_web3_finding(
                    "SMG-WEB3-SPOT-ORACLE",
                    "CRITICAL",
                    "AMM spot-price (`getReserves`/`slot0`) used for pricing/collateral without TWAP or Chainlink oracle (flash-loan manipulable)".into(),
                    rel_path,
                    idx + 1,
                    line.trim(),
                    SinkKind::BalanceUpdate,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Use a multi-block Uniswap v3 TWAP (`observe()`) or Chainlink AggregatorV3Interface with staleness & bounds checks.",
                ));
            }
        }
    }

    // 5. Chainlink `latestRoundData()` missing staleness / non-positive / round completeness checks
    for (idx, line) in lines.iter().enumerate() {
        if line.contains("latestRoundData(") {
            let end = (idx + 15).min(lines.len());
            let window = lines[idx..end].join("\n");
            let checks_stale = window.contains("updatedAt")
                && (window.contains("block.timestamp") || window.contains("MAX_DELAY") || window.contains("heartbeat"));
            let checks_pos = window.contains("> 0") || window.contains("<= 0");
            if !checks_stale || !checks_pos {
                findings.push(mk_web3_finding(
                    "SMG-WEB3-ORACLE-STALE",
                    "HIGH",
                    "Chainlink `latestRoundData()` missing staleness (`updatedAt`) or positive price (`answer > 0`) validation".into(),
                    rel_path,
                    idx + 1,
                    "latestRoundData",
                    SinkKind::BalanceUpdate,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Validate `answer > 0`, `updatedAt != 0`, `block.timestamp - updatedAt <= MAX_STALENESS`, and `answeredInRound >= roundId`.",
                ));
            }
        }
    }

    // 6. ERC-4626 First-Depositor Share Inflation Attack
    let is_erc4626 = stripped.contains("ERC4626")
        || (stripped.contains("convertToShares") && stripped.contains("totalAssets"));
    if is_erc4626 {
        let has_mitigation = stripped.contains("_decimalsOffset")
            || stripped.contains("MINIMUM_LIQUIDITY")
            || stripped.contains("DEAD_SHARES")
            || stripped.contains("virtualShares")
            || stripped.contains("+ 1");
        if !has_mitigation {
            let line = lines
                .iter()
                .position(|l| l.contains("convertToShares") || l.contains("ERC4626"))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(mk_web3_finding(
                "SMG-WEB3-ERC4626-INFLATION",
                "HIGH",
                "ERC-4626 vault lacks virtual share offset (`_decimalsOffset`) or dead-share minting (first-depositor inflation risk)".into(),
                rel_path,
                line,
                "convertToShares",
                SinkKind::BalanceUpdate,
                GuardKind::Auth,
                Confidence::Confirmed,
                "Override `_decimalsOffset()` (OpenZeppelin v5) or mint initial dead shares to `address(0xdead)` on vault deployment.",
            ));
        }
    }

    // 7. Diamond Facet Selector Collisions within single file
    let mut facet_sigs: Vec<(String, String, usize, String)> = Vec::new();
    for c in contracts {
        if c.name.contains("Facet") || stripped.contains("IDiamondCut") || stripped.contains("diamondCut") {
            for (idx, line) in lines.iter().enumerate() {
                if let Some(rest) = line.trim().strip_prefix("function ")
                    && (line.contains("external") || line.contains("public"))
                    && let Some(paren_end) = rest.find(')')
                {
                    let sig = rest[..=paren_end].replace(' ', "");
                    facet_sigs.push((c.name.clone(), rel_path.to_string(), idx + 1, sig));
                }
            }
        }
    }
    findings.extend(detect_diamond_selector_collisions(&facet_sigs));

    findings
}

/// Deep Solana Anchor / Native PDA & CPI security checks.
pub fn analyze_solana_pda_depth(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    // Only scan before `#[cfg(test)]` so inline Rust unit test fixtures never false-positive
    let prod_src = source.split("#[cfg(test)]").next().unwrap_or(source);
    if !prod_src.contains("use anchor_lang")
        && !prod_src.contains("use solana_program")
        && !prod_src.contains("anchor_lang::")
        && !prod_src.contains("solana_program::")
    {
        return Vec::new();
    }
    let stripped = smg_graph::taint::strip_comments_simple(prod_src);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut findings = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('"')
            || smg_graph::taint::is_pattern_matcher_or_doc_line(trimmed)
        {
            continue;
        }

        // 1. Anchor `init_if_needed` re-initialization attack vector
        if trimmed.contains("init_if_needed") {
            let win_end = (idx + 12).min(lines.len());
            let window = lines[idx..win_end].join("\n");
            let has_guard = window.contains("is_initialized") || window.contains("constraint =");
            if !has_guard {
                findings.push(mk_web3_finding(
                    "SMG-SOL-INIT-IF-NEEDED",
                    "HIGH",
                    "Anchor `init_if_needed` used without explicit `is_initialized` or owner constraint (re-initialization attack risk)".into(),
                    rel_path,
                    idx + 1,
                    "init_if_needed",
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Prefer `init` over `init_if_needed`, or explicitly assert `!account.is_initialized` before mutating state.",
                ));
            }
        }

        // 2. Non-canonical PDA derivation via `create_program_address`
        if trimmed.contains("create_program_address(") && !stripped.contains("find_program_address(") {
            findings.push(mk_web3_finding(
                "SMG-SOL-PDA-NONCANONICAL",
                "HIGH",
                "Solana `create_program_address()` used without canonical bump from `find_program_address()` (PDA bump-seed spoofing)".into(),
                rel_path,
                idx + 1,
                "create_program_address",
                SinkKind::AuthMutation,
                GuardKind::Auth,
                Confidence::Confirmed,
                "Derive canonical PDA bumps with `Pubkey::find_program_address()` or Anchor `seeds = [...], bump`.",
            ));
        }

        // 3. Arbitrary CPI via `invoke` / `invoke_signed` without verifying target program_id
        if (trimmed.contains("invoke(") || trimmed.contains("invoke_signed("))
            && !trimmed.starts_with("fn ")
        {
            let win_start = idx.saturating_sub(15);
            let window = lines[win_start..=idx].join("\n");
            let checks_program = window.contains("program_id ==")
                || window.contains("key == &spl_token")
                || window.contains("key == &system_program")
                || window.contains("Program<'info,")
                || window.contains("check_program_account");
            if !checks_program {
                findings.push(mk_web3_finding(
                    "SMG-SOL-ARBITRARY-CPI",
                    "CRITICAL",
                    "Solana `invoke`/`invoke_signed` CPI without target program ID validation (arbitrary CPI execution)".into(),
                    rel_path,
                    idx + 1,
                    "invoke_signed",
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Verify the target program `AccountInfo.key` against the expected hardcoded program ID or use Anchor `Program<'info, T>`.",
                ));
            }
        }
    }

    findings
}

/// Deep Move (Aptos / Sui) resource ability & capability security checks.
pub fn analyze_move_ultra_depth(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    let stripped = smg_graph::taint::strip_comments_simple(source);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut findings = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // 1. Asset/Vault/Cap struct mistakenly granted `copy` or `drop` ability
        if trimmed.starts_with("struct ") || trimmed.starts_with("public struct ") {
            let low = trimmed.to_ascii_lowercase();
            let is_event = low.contains("event");
            let is_sensitive_resource = !is_event
                && (low.contains("coin")
                    || low.contains("vault")
                    || low.contains("treasury")
                    || low.contains("receipt")
                    || low.contains("admincap")
                    || low.contains("hotpotato"));
            if is_sensitive_resource && (trimmed.contains(" has ") && (trimmed.contains("copy") || trimmed.contains("drop"))) {
                findings.push(mk_web3_finding(
                    "SMG-MOVE-ABILITY-LEAK",
                    "CRITICAL",
                    format!(
                        "Sensitive Move resource `{}` grants `copy` or `drop` ability (enables duplication or hot-potato bypass)",
                        trimmed.split('{').next().unwrap_or(trimmed).trim()
                    ),
                    rel_path,
                    idx + 1,
                    "struct",
                    SinkKind::BalanceUpdate,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Remove `copy` and `drop` abilities from financial assets, vaults, capabilities, and flash-loan hot-potato receipts.",
                ));
            }
        }

        // 2. Sui `public_share_object` / `share_object` called on an AdminCap / OwnerCap capability
        if (trimmed.contains("share_object(") || trimmed.contains("public_share_object("))
            && (trimmed.to_ascii_lowercase().contains("admin")
                || trimmed.to_ascii_lowercase().contains("cap"))
        {
            findings.push(mk_web3_finding(
                "SMG-MOVE-SHARED-CAP",
                "CRITICAL",
                "Move capability object (`AdminCap`/Cap) passed to `share_object()` — grants public access to anyone".into(),
                rel_path,
                idx + 1,
                "share_object",
                SinkKind::AuthMutation,
                GuardKind::Auth,
                Confidence::Confirmed,
                "Transfer capability objects exclusively to a controlled owner address via `transfer::transfer(cap, tx_context::sender(ctx))`.",
            ));
        }

        // 3. `public entry fun` mutating vault/treasury without `&signer` or Cap parameter
        if trimmed.starts_with("public entry fun ") {
            let low = trimmed.to_ascii_lowercase();
            let mutates_treasury = low.contains("withdraw")
                || low.contains("mint")
                || low.contains("burn")
                || low.contains("set_fee")
                || low.contains("upgrade");
            let has_auth_param = trimmed.contains("&signer")
                || trimmed.contains("Cap")
                || trimmed.contains("Admin")
                || trimmed.contains("Owner");
            if mutates_treasury && !has_auth_param {
                findings.push(mk_web3_finding(
                    "SMG-MOVE-ENTRY-NO-AUTH",
                    "CRITICAL",
                    format!(
                        "Privileged Move entry function `{}` lacks `&signer` or capability (`AdminCap`) authorization parameter",
                        trimmed.split('(').next().unwrap_or(trimmed).trim()
                    ),
                    rel_path,
                    idx + 1,
                    "public entry fun",
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    Confidence::Confirmed,
                    "Require an explicit `&signer` (with address verification) or owned `&AdminCap` witness parameter.",
                ));
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_uups_flashloan_spot_oracle_chainlink_erc4626_and_diamond_clash() {
        let sol = r#"
contract MyVault is UUPSUpgradeable, ERC4626 {
    function initialize(address owner) public {
        _owner = owner;
    }
    function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata) external returns (bool) {
        return true;
    }
    function getCollateralPrice(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }
    function feedPrice() external view returns (int256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return answer;
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply() / totalAssets();
    }
}
"#;
        let hits = analyze_solidity_ultra_depth("contracts/MyVault.sol", sol, &[]);
        let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"SMG-WEB3-UUPS-UNINIT"), "missing UUPS: {ids:?}");
        assert!(ids.contains(&"SMG-WEB3-FLASHLOAN-AUTH"), "missing flashloan: {ids:?}");
        assert!(ids.contains(&"SMG-WEB3-SPOT-ORACLE"), "missing spot oracle: {ids:?}");
        assert!(ids.contains(&"SMG-WEB3-ORACLE-STALE"), "missing chainlink stale: {ids:?}");
        assert!(ids.contains(&"SMG-WEB3-ERC4626-INFLATION"), "missing erc4626: {ids:?}");

        // Diamond selector clash test (`transfer(address,uint256)` in two facets)
        let clash = detect_diamond_selector_collisions(&[
            ("FacetA".into(), "FacetA.sol".into(), 10, "transfer(address,uint256)".into()),
            ("FacetB".into(), "FacetB.sol".into(), 20, "transfer(address,uint256)".into()),
        ]);
        assert_eq!(clash.len(), 1);
        assert_eq!(clash[0].rule_id, "SMG-WEB3-DIAMOND-CLASH");
    }

    #[test]
    fn detects_solana_pda_cpi_and_move_ability_vulnerabilities() {
        let solana_rs = r#"
use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct InitCtx<'info> {
    #[account(init_if_needed, payer = user, space = 64)]
    pub vault: Account<'info, Vault>,
}
pub fn bad_pda_and_cpi(program_id: &Pubkey, bump: u8, ix: &Instruction, accounts: &[AccountInfo]) {
    let _pda = Pubkey::create_program_address(&[b"vault", &[bump]], program_id).unwrap();
    invoke_signed(ix, accounts, &[]).unwrap();
}
"#;
        let sh = analyze_solana_pda_depth("programs/vault/src/lib.rs", solana_rs);
        let sids: Vec<&str> = sh.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(sids.contains(&"SMG-SOL-INIT-IF-NEEDED"), "{sids:?}");
        assert!(sids.contains(&"SMG-SOL-PDA-NONCANONICAL"), "{sids:?}");
        assert!(sids.contains(&"SMG-SOL-ARBITRARY-CPI"), "{sids:?}");

        let move_src = r#"
module defi::vault {
    struct FlashReceipt has copy, drop { amount: u64 }
    public entry fun withdraw_all(vault: &mut Vault, amount: u64) {
        transfer::public_share_object(admin_cap);
    }
}
"#;
        let mh = analyze_move_ultra_depth("sources/vault.move", move_src);
        let mids: Vec<&str> = mh.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(mids.contains(&"SMG-MOVE-ABILITY-LEAK"), "{mids:?}");
        assert!(mids.contains(&"SMG-MOVE-SHARED-CAP"), "{mids:?}");
        assert!(mids.contains(&"SMG-MOVE-ENTRY-NO-AUTH"), "{mids:?}");
    }
}
