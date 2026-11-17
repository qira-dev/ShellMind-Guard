use revm::primitives::{B256, U256, keccak256};
use serde_json::Value;
use smg_core::{IndexedFile, Language};
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Canonical EIP-1967 implementation slot: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1).
pub fn eip1967_implementation_slot() -> U256 {
    let h: B256 = keccak256(b"eip1967.proxy.implementation");
    U256::from_be_bytes(h.0).wrapping_sub(U256::from(1u64))
}

/// Canonical EIP-1967 admin slot: bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1).
pub fn eip1967_admin_slot() -> U256 {
    let h: B256 = keccak256(b"eip1967.proxy.admin");
    U256::from_be_bytes(h.0).wrapping_sub(U256::from(1u64))
}

/// Canonical EIP-1967 beacon slot: bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1).
pub fn eip1967_beacon_slot() -> U256 {
    let h: B256 = keccak256(b"eip1967.proxy.beacon");
    U256::from_be_bytes(h.0).wrapping_sub(U256::from(1u64))
}

/// ERC-7201 namespaced storage base slot: keccak256(uint256(keccak256(id)) - 1) & ~0xff.
pub fn erc7201_namespace_slot(namespace_id: &str) -> U256 {
    let inner =
        U256::from_be_bytes(keccak256(namespace_id.as_bytes()).0).wrapping_sub(U256::from(1u64));
    let mut bytes = inner.to_be_bytes::<32>();
    let outer = keccak256(bytes);
    bytes = outer.0;
    bytes[31] = 0;
    U256::from_be_bytes(bytes)
}

/// Exact EVM Solidity mapping storage slot: keccak256(key_256 || base_slot_256).
pub fn mapping_storage_slot(key_32: [u8; 32], base_slot: U256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&key_32);
    preimage[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    keccak256(preimage)
}

/// Exact EVM Solidity dynamic array element slot: (keccak256(base_slot_256) + index * elem_slots) mod 2^256.
pub fn dynamic_array_storage_slot(base_slot: U256, index: u64, elem_slots: u64) -> U256 {
    let base_hash = U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0);
    base_hash.wrapping_add(U256::from(index).wrapping_mul(U256::from(elem_slots)))
}

/// Computes the 4-byte ABI selector for a canonical signature (e.g. `withdraw(uint256)`).
pub fn abi_selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmSlotEntry {
    pub contract: String,
    pub var_name: String,
    pub var_type: String,
    pub slot: U256,
    pub byte_offset: u8,
    pub byte_len: u8,
    pub rel_path: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct StateVarSpec {
    pub name: String,
    pub var_type: String,
    pub is_constant_or_immutable: bool,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct CompiledContractArtifact {
    pub name: String,
    pub rel_path: String,
    pub deployed_bytecode: Vec<u8>,
    pub creation_bytecode: Vec<u8>,
    pub abi_functions: Vec<String>,
    pub storage_slots: Vec<EvmSlotEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct Web3Context {
    pub artifacts: HashMap<String, CompiledContractArtifact>,
    pub is_foundry: bool,
    pub is_hardhat: bool,
    pub is_anchor: bool,
    pub is_move: bool,
}

/// Returns EVM byte width for common Solidity primitive/reference storage types.
pub fn solidity_type_byte_width(raw_type: &str) -> u8 {
    let t = raw_type.trim();
    if t == "bool" || t == "uint8" || t == "int8" {
        return 1;
    }
    if t == "address" || t == "address payable" {
        return 20;
    }
    if let Some(rest) = t.strip_prefix("uint").or_else(|| t.strip_prefix("int"))
        && let Ok(bits) = rest.parse::<u16>()
        && (8..=256).contains(&bits)
        && bits % 8 == 0
    {
        return (bits / 8) as u8;
    }
    if let Some(rest) = t.strip_prefix("bytes")
        && !rest.is_empty()
        && let Ok(n) = rest.parse::<u8>()
        && (1..=32).contains(&n)
    {
        return n;
    }
    // mappings, dynamic arrays, strings, bytes, structs default to full slot alignment unless known
    32
}

/// Packs Solidity state variables sequentially using 256-bit EVM slot packing rules.
pub fn pack_storage_vars(
    contract: &str,
    rel_path: &str,
    vars: &[StateVarSpec],
    start_slot: u64,
) -> Vec<EvmSlotEntry> {
    let mut entries = Vec::new();
    let mut cur_slot = start_slot;
    let mut cur_off: u8 = 0;

    for v in vars {
        if v.is_constant_or_immutable {
            continue;
        }
        let clean_ty = v.var_type.trim();
        // Fixed static arrays `T[N]` reserve N slots (or packed slots)
        let width = solidity_type_byte_width(clean_ty);
        if width == 32 {
            if cur_off > 0 {
                cur_slot += 1;
                cur_off = 0;
            }
            entries.push(EvmSlotEntry {
                contract: contract.to_string(),
                var_name: v.name.clone(),
                var_type: clean_ty.to_string(),
                slot: U256::from(cur_slot),
                byte_offset: 0,
                byte_len: 32,
                rel_path: rel_path.to_string(),
                line: v.line,
            });
            let slots_consumed = parse_fixed_array_slots(clean_ty).unwrap_or(1);
            cur_slot += slots_consumed;
        } else {
            if cur_off + width > 32 {
                cur_slot += 1;
                cur_off = 0;
            }
            entries.push(EvmSlotEntry {
                contract: contract.to_string(),
                var_name: v.name.clone(),
                var_type: clean_ty.to_string(),
                slot: U256::from(cur_slot),
                byte_offset: cur_off,
                byte_len: width,
                rel_path: rel_path.to_string(),
                line: v.line,
            });
            cur_off += width;
            if cur_off >= 32 {
                cur_slot += 1;
                cur_off = 0;
            }
        }
    }
    entries
}

fn parse_fixed_array_slots(ty: &str) -> Option<u64> {
    let lb = ty.rfind('[')?;
    let rb = ty.rfind(']')?;
    if rb <= lb + 1 {
        return None;
    }
    let count = ty[lb + 1..rb].trim().parse::<u64>().ok()?;
    let elem = ty[..lb].trim();
    let w = solidity_type_byte_width(elem) as u64;
    if w == 0 || count == 0 {
        return Some(1);
    }
    let per_slot = 32 / w;
    Some(count.div_ceil(per_slot.max(1)))
}

fn is_canonical_upgrade_slot(slot: U256) -> bool {
    slot == eip1967_implementation_slot()
        || slot == eip1967_admin_slot()
        || slot == eip1967_beacon_slot()
}

/// Checks slot-level storage disjointness between delegatecall proxies and implementation contracts.
pub fn detect_proxy_storage_collisions(
    proxies: &[(String, String, Vec<EvmSlotEntry>)],
    implementations: &[(String, String, Vec<EvmSlotEntry>)],
) -> Vec<LocalStaticFinding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, usize)> = HashSet::new();

    for (proxy_name, proxy_path, proxy_slots) in proxies {
        for (impl_name, _impl_path, impl_slots) in implementations {
            if proxy_name == impl_name {
                continue;
            }
            for ps in proxy_slots {
                if is_canonical_upgrade_slot(ps.slot) || ps.var_name.starts_with("__gap") {
                    continue;
                }
                for is in impl_slots {
                    if is_canonical_upgrade_slot(is.slot) || is.var_name.starts_with("__gap") {
                        continue;
                    }
                    if ps.slot != is.slot {
                        continue;
                    }
                    let ps_end = ps.byte_offset.saturating_add(ps.byte_len);
                    let is_end = is.byte_offset.saturating_add(is.byte_len);
                    let overlaps = ps.byte_offset < is_end && is.byte_offset < ps_end;
                    if overlaps && (ps.var_name != is.var_name || ps.var_type != is.var_type) {
                        let key = (proxy_path.clone(), ps.line);
                        if seen.insert(key) {
                            findings.push(LocalStaticFinding {
                                rule_id: "SMG-WEB3-STORAGE".to_string(),
                                severity: "CRITICAL".to_string(),
                                title: format!(
                                    "Storage collision at slot {}: proxy `{}.{}` ({}) overlaps `{}.{}` ({})",
                                    ps.slot,
                                    proxy_name,
                                    ps.var_name,
                                    ps.var_type,
                                    impl_name,
                                    is.var_name,
                                    is.var_type
                                ),
                                rel_path: proxy_path.clone(),
                                line: ps.line,
                                symbol: format!("{proxy_name}.{}", ps.var_name),
                                sink_kind: SinkKind::Misconfiguration,
                                missing_guard: GuardKind::ConfigPolicy,
                                confidence: Confidence::Confirmed,
                                remediation: "Store proxy state strictly in canonical EIP-1967 or ERC-7201 namespaced slots so delegatecall implementations cannot overwrite proxy pointers.".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    findings
}

/// Discovers Web3 manifests and ingests Foundry (`out/*.json`) / Hardhat compiler artifacts if present.
pub fn ingest_web3_context(project_root: &Path, files: &[IndexedFile]) -> Web3Context {
    let mut ctx = Web3Context {
        is_foundry: project_root.join("foundry.toml").exists(),
        is_hardhat: project_root.join("hardhat.config.js").exists()
            || project_root.join("hardhat.config.ts").exists(),
        is_anchor: project_root.join("Anchor.toml").exists(),
        is_move: project_root.join("Move.toml").exists(),
        ..Default::default()
    };

    for f in files {
        match f.language {
            Language::Solidity => ctx.is_foundry = true,
            Language::Move => ctx.is_move = true,
            _ => {}
        }
    }

    for dir in ["out", "artifacts", "build/contracts"] {
        let p = project_root.join(dir);
        if p.is_dir() {
            collect_json_artifacts(&p, project_root, &mut ctx.artifacts, 0);
        }
    }
    ctx
}

fn collect_json_artifacts(
    dir: &Path,
    root: &Path,
    out: &mut HashMap<String, CompiledContractArtifact>,
    depth: usize,
) {
    if depth > 4 || out.len() >= 128 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_json_artifacts(&p, root, out, depth + 1);
            continue;
        }
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&p) else {
            continue;
        };
        if raw.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(art) = parse_foundry_or_hardhat_artifact(&p, root, &val) {
            out.insert(art.name.clone(), art);
        }
    }
}

fn decode_hex_bytecode(hex_str: &str) -> Vec<u8> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let Ok(b) = u8::from_str_radix(&clean[i..i + 2], 16) else {
            return Vec::new();
        };
        out.push(b);
    }
    out
}

fn parse_foundry_or_hardhat_artifact(
    path: &Path,
    root: &Path,
    val: &Value,
) -> Option<CompiledContractArtifact> {
    let has_bytecode = val.get("deployedBytecode").is_some() || val.get("bytecode").is_some();
    let has_abi = val.get("abi").and_then(|a| a.as_array()).is_some();
    if !has_bytecode && !has_abi {
        return None;
    }
    let contract_name = val
        .get("contractName")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })?;
    let rel_path = val
        .pointer("/ast/absolutePath")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            path.strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        });

    let deployed_hex = val
        .pointer("/deployedBytecode/object")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("deployedBytecode").and_then(|v| v.as_str()))
        .unwrap_or("");
    let creation_hex = val
        .pointer("/bytecode/object")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("bytecode").and_then(|v| v.as_str()))
        .unwrap_or("");

    let mut abi_functions = Vec::new();
    if let Some(arr) = val.get("abi").and_then(|v| v.as_array()) {
        for item in arr {
            if item.get("type").and_then(|v| v.as_str()) == Some("function")
                && let Some(name) = item.get("name").and_then(|v| v.as_str())
            {
                let params: Vec<&str> = item
                    .get("inputs")
                    .and_then(|v| v.as_array())
                    .map(|xs| {
                        xs.iter()
                            .filter_map(|x| x.get("type").and_then(|t| t.as_str()))
                            .collect()
                    })
                    .unwrap_or_default();
                abi_functions.push(format!("{name}({})", params.join(",")));
            }
        }
    }

    let mut storage_slots = Vec::new();
    if let Some(storage_arr) = val
        .pointer("/storageLayout/storage")
        .and_then(|v| v.as_array())
    {
        for entry in storage_arr {
            let Some(label) = entry.get("label").and_then(|v| v.as_str()) else {
                continue;
            };
            let slot_str = entry.get("slot").and_then(|v| v.as_str()).unwrap_or("0");
            let slot = U256::from_str_radix(slot_str, 10).unwrap_or(U256::ZERO);
            let offset = entry.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            let ty_id = entry
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("t_uint256");
            let byte_len = val
                .pointer(&format!("/storageLayout/types/{ty_id}/numberOfBytes"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(32);
            let ty_label = val
                .pointer(&format!("/storageLayout/types/{ty_id}/label"))
                .and_then(|v| v.as_str())
                .unwrap_or(ty_id);
            storage_slots.push(EvmSlotEntry {
                contract: contract_name.clone(),
                var_name: label.to_string(),
                var_type: ty_label.to_string(),
                slot,
                byte_offset: offset,
                byte_len,
                rel_path: rel_path.clone(),
                line: 1,
            });
        }
    }

    Some(CompiledContractArtifact {
        name: contract_name,
        rel_path,
        deployed_bytecode: decode_hex_bytecode(deployed_hex),
        creation_bytecode: decode_hex_bytecode(creation_hex),
        abi_functions,
        storage_slots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_exact_erc1967_erc7201_and_mapping_slots() {
        let impl_slot = eip1967_implementation_slot();
        // Canonical ERC-1967 implementation slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        assert_eq!(
            format!("{:#066x}", impl_slot),
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        );
        let ns = erc7201_namespace_slot("openzeppelin.storage.Ownable");
        assert_eq!(ns.to_be_bytes::<32>()[31], 0);

        let key = [0xAA; 32];
        let s1 = mapping_storage_slot(key, U256::ZERO);
        let s2 = mapping_storage_slot(key, U256::from(1u64));
        assert_ne!(s1, s2);

        let d0 = dynamic_array_storage_slot(U256::from(2u64), 0, 1);
        let d1 = dynamic_array_storage_slot(U256::from(2u64), 1, 1);
        assert_eq!(d1 - d0, U256::from(1u64));
    }

    #[test]
    fn packs_slots_and_detects_proxy_collision_while_sparing_identical_layout() {
        let proxy_vars = vec![
            StateVarSpec {
                name: "implementation".into(),
                var_type: "address".into(),
                is_constant_or_immutable: false,
                line: 4,
            },
            StateVarSpec {
                name: "paused".into(),
                var_type: "bool".into(),
                is_constant_or_immutable: false,
                line: 5,
            },
        ];
        let impl_bad = vec![StateVarSpec {
            name: "owner".into(),
            var_type: "address".into(),
            is_constant_or_immutable: false,
            line: 9,
        }];
        let p_slots = pack_storage_vars("BadProxy", "contracts/Proxy.sol", &proxy_vars, 0);
        let i_slots = pack_storage_vars("ImplBad", "contracts/Impl.sol", &impl_bad, 0);
        // `implementation` (20B) + `paused` (1B) pack into slot 0, colliding with Impl.owner at slot 0.
        assert_eq!(p_slots[0].slot, U256::ZERO);
        assert_eq!(p_slots[1].slot, U256::ZERO);
        assert_eq!(p_slots[1].byte_offset, 20);
        let hits = detect_proxy_storage_collisions(
            &[("BadProxy".into(), "contracts/Proxy.sol".into(), p_slots)],
            &[("ImplBad".into(), "contracts/Impl.sol".into(), i_slots)],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "SMG-WEB3-STORAGE");
    }
}
