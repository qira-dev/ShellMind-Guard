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
    /// Keyed by `(rel_path, contract_name)` so identically named contracts across directories never collide.
    pub artifacts_by_path: HashMap<(String, String), CompiledContractArtifact>,
    pub is_foundry: bool,
    pub is_hardhat: bool,
    pub is_anchor: bool,
    pub is_move: bool,
}

impl Web3Context {
    /// Looks up a compiled contract artifact preferring exact `(rel_path, name)` match,
    /// then suffix match on `rel_path`, falling back to `artifacts.get(name)`.
    pub fn lookup_artifact(&self, rel_path: &str, name: &str) -> Option<&CompiledContractArtifact> {
        let norm = rel_path.replace('\\', "/");
        if let Some(a) = self
            .artifacts_by_path
            .get(&(norm.clone(), name.to_string()))
        {
            return Some(a);
        }
        if let Some((_, a)) = self
            .artifacts_by_path
            .iter()
            .find(|((p, n), _)| n == name && (p.ends_with(&norm) || norm.ends_with(p.as_str())))
        {
            return Some(a);
        }
        self.artifacts.get(name)
    }
}

/// Returns EVM byte width for common Solidity primitive/reference storage types.
pub fn solidity_type_byte_width(raw_type: &str) -> u8 {
    solidity_type_byte_width_with_defs(raw_type, &HashSet::new(), &HashSet::new())
}

pub fn solidity_type_byte_width_with_defs(
    raw_type: &str,
    enums: &HashSet<String>,
    contracts_and_interfaces: &HashSet<String>,
) -> u8 {
    let t = raw_type.trim();
    if t == "bool" || t == "uint8" || t == "int8" || enums.contains(t) {
        return 1;
    }
    if t == "address"
        || t == "address payable"
        || contracts_and_interfaces.contains(t)
        || (t.starts_with('I')
            && t.len() >= 2
            && t.as_bytes()[1].is_ascii_uppercase()
            && !t.contains('[')
            && !t.contains(' '))
    {
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
    pack_storage_vars_with_defs(
        contract,
        rel_path,
        vars,
        start_slot,
        &HashSet::new(),
        &HashSet::new(),
    )
}

pub fn pack_storage_vars_with_defs(
    contract: &str,
    rel_path: &str,
    vars: &[StateVarSpec],
    start_slot: u64,
    enums: &HashSet<String>,
    contracts_and_interfaces: &HashSet<String>,
) -> Vec<EvmSlotEntry> {
    let mut entries = Vec::new();
    let mut cur_slot = start_slot;
    let mut cur_off: u8 = 0;

    for v in vars {
        if v.is_constant_or_immutable {
            continue;
        }
        let clean_ty = v.var_type.trim();
        // Fixed static arrays `T[N]` or `T[M][N]` always start on a new 32-byte slot boundary
        if let Some(slots_consumed) =
            parse_fixed_array_slots_with_defs(clean_ty, enums, contracts_and_interfaces)
        {
            if cur_off > 0 {
                cur_slot += 1;
                cur_off = 0;
            }
            let span = slots_consumed.max(1);
            for s in 0..span.min(64) {
                entries.push(EvmSlotEntry {
                    contract: contract.to_string(),
                    var_name: v.name.clone(),
                    var_type: clean_ty.to_string(),
                    slot: U256::from(cur_slot + s),
                    byte_offset: 0,
                    byte_len: 32,
                    rel_path: rel_path.to_string(),
                    line: v.line,
                });
            }
            cur_slot += span;
            continue;
        }

        let width = solidity_type_byte_width_with_defs(clean_ty, enums, contracts_and_interfaces);
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
            cur_slot += 1;
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

pub fn parse_fixed_array_slots(ty: &str) -> Option<u64> {
    parse_fixed_array_slots_with_defs(ty, &HashSet::new(), &HashSet::new())
}

fn parse_fixed_array_slots_with_defs(
    ty: &str,
    enums: &HashSet<String>,
    contracts_and_interfaces: &HashSet<String>,
) -> Option<u64> {
    let trimmed = ty.trim();
    if !trimmed.ends_with(']') {
        return None;
    }
    let lb = trimmed.rfind('[')?;
    let rb = trimmed.len() - 1;
    if rb <= lb + 1 {
        // Dynamic array `T[]` occupies 1 base length slot
        return None;
    }
    let count = trimmed[lb + 1..rb].trim().parse::<u64>().ok()?;
    let elem = trimmed[..lb].trim();
    if let Some(inner_slots) =
        parse_fixed_array_slots_with_defs(elem, enums, contracts_and_interfaces)
    {
        return Some(count.saturating_mul(inner_slots.max(1)).max(1));
    }
    let w = solidity_type_byte_width_with_defs(elem, enums, contracts_and_interfaces) as u64;
    if w == 0 || count == 0 {
        return Some(1);
    }
    let per_slot = (32 / w).max(1);
    Some(count.div_ceil(per_slot))
}

fn is_canonical_upgrade_slot(slot: U256) -> bool {
    slot == eip1967_implementation_slot()
        || slot == eip1967_admin_slot()
        || slot == eip1967_beacon_slot()
}

fn contract_family_stem(name: &str) -> String {
    let mut s = name.to_ascii_lowercase();
    for token in [
        "transparentupgradeableproxy",
        "upgradeableproxy",
        "uupsproxy",
        "proxy",
        "implementation",
        "impl",
        "logic",
        "v1",
        "v2",
        "v3",
    ] {
        s = s.replace(token, "");
    }
    s.trim_matches('_').to_string()
}

fn are_proxy_and_impl_paired(
    proxy_name: &str,
    proxy_path: &str,
    impl_name: &str,
    impl_path: &str,
    total_proxies: usize,
) -> bool {
    if proxy_path == impl_path {
        return true;
    }
    let p_stem = contract_family_stem(proxy_name);
    let i_stem = contract_family_stem(impl_name);
    if !p_stem.is_empty() && !i_stem.is_empty() {
        if p_stem == i_stem || p_stem.contains(&i_stem) || i_stem.contains(&p_stem) {
            return true;
        }
        // Distinct explicit family stems across different files (e.g., `TokenAProxy` vs `TokenBImpl`)
        return false;
    }
    // Generic proxy name (`Proxy`) pairs when it is the single proxy in the scan
    total_proxies == 1
}

/// Checks slot-level storage disjointness between paired delegatecall proxies and implementation contracts.
pub fn detect_proxy_storage_collisions(
    proxies: &[(String, String, Vec<EvmSlotEntry>)],
    implementations: &[(String, String, Vec<EvmSlotEntry>)],
) -> Vec<LocalStaticFinding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, usize)> = HashSet::new();

    for (proxy_name, proxy_path, proxy_slots) in proxies {
        for (impl_name, impl_path, impl_slots) in implementations {
            if proxy_name == impl_name
                || !are_proxy_and_impl_paired(
                    proxy_name,
                    proxy_path,
                    impl_name,
                    impl_path,
                    proxies.len(),
                )
            {
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
            collect_json_artifacts(
                &p,
                project_root,
                &mut ctx.artifacts,
                &mut ctx.artifacts_by_path,
                0,
            );
        }
    }
    ctx
}

fn collect_json_artifacts(
    dir: &Path,
    root: &Path,
    out: &mut HashMap<String, CompiledContractArtifact>,
    out_by_path: &mut HashMap<(String, String), CompiledContractArtifact>,
    depth: usize,
) {
    if depth > 4 || out.len() >= 128 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for ent in entries {
        if out.len() >= 128 {
            break;
        }
        let p = ent.path();
        if p.is_dir() {
            collect_json_artifacts(&p, root, out, out_by_path, depth + 1);
            continue;
        }
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(meta) = ent.metadata() else {
            continue;
        };
        if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&p) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(art) = parse_foundry_or_hardhat_artifact(&p, root, &val) {
            out_by_path.insert((art.rel_path.clone(), art.name.clone()), art.clone());
            out.insert(art.name.clone(), art);
        }
    }
}

/// Links Solidity library placeholders (`__$34-hex$__` or `__LibName___...`) to a deterministic
/// 20-byte mock library address (`0x0000000000000000000000000000000000003333`) before hex decoding.
pub fn link_library_placeholders(hex_str: &str) -> String {
    const MOCK_LIB_ADDR_HEX: &str = "0000000000000000000000000000000000003333";
    let trimmed = hex_str.trim();
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if !clean.contains("__") {
        return clean.to_string();
    }
    let bytes = clean.as_bytes();
    let mut out = String::with_capacity(clean.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 40 <= bytes.len() && bytes[i] == b'_' && bytes[i + 1] == b'_' {
            let slice = &bytes[i..i + 40];
            let is_solc_v5 =
                slice.starts_with(&[b'_', b'_', 0x24]) && slice.ends_with(&[0x24, b'_', b'_']);
            if is_solc_v5 || slice.ends_with(b"__") {
                out.push_str(MOCK_LIB_ADDR_HEX);
                i += 40;
                continue;
            }
        }
        if bytes[i].is_ascii() {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

pub fn decode_hex_bytecode(hex_str: &str) -> Vec<u8> {
    if !hex_str.is_ascii() {
        return Vec::new();
    }
    let linked = link_library_placeholders(hex_str);
    let clean = linked.as_str();
    if clean.is_empty() || !clean.is_ascii() || !clean.len().is_multiple_of(2) {
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
            let total_bytes = val
                .pointer(&format!("/storageLayout/types/{ty_id}/numberOfBytes"))
                .and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| v.as_u64())
                })
                .unwrap_or(32);
            let ty_label = val
                .pointer(&format!("/storageLayout/types/{ty_id}/label"))
                .and_then(|v| v.as_str())
                .unwrap_or(ty_id);
            if total_bytes <= 32 {
                storage_slots.push(EvmSlotEntry {
                    contract: contract_name.clone(),
                    var_name: label.to_string(),
                    var_type: ty_label.to_string(),
                    slot,
                    byte_offset: offset,
                    byte_len: total_bytes.max(1) as u8,
                    rel_path: rel_path.clone(),
                    line: 1,
                });
            } else {
                let num_slots = total_bytes.div_ceil(32).min(64);
                for s in 0..num_slots {
                    storage_slots.push(EvmSlotEntry {
                        contract: contract_name.clone(),
                        var_name: label.to_string(),
                        var_type: ty_label.to_string(),
                        slot: slot.wrapping_add(U256::from(s)),
                        byte_offset: 0,
                        byte_len: 32,
                        rel_path: rel_path.clone(),
                        line: 1,
                    });
                }
            }
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
        // Official EIP-7201 specification test vectors:
        assert_eq!(
            format!("{:#066x}", erc7201_namespace_slot("example.main")),
            "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500"
        );
        assert_eq!(
            format!(
                "{:#066x}",
                erc7201_namespace_slot("openzeppelin.storage.ERC20")
            ),
            "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00"
        );

        let key = [0xAA; 32];
        let s1 = mapping_storage_slot(key, U256::ZERO);
        let s2 = mapping_storage_slot(key, U256::from(1u64));
        assert_ne!(s1, s2);

        let d0 = dynamic_array_storage_slot(U256::from(2u64), 0, 1);
        let d1 = dynamic_array_storage_slot(U256::from(2u64), 1, 1);
        assert_eq!(d1 - d0, U256::from(1u64));
    }

    #[test]
    fn packs_slots_multidim_arrays_and_pairs_proxies_without_cross_contract_fp() {
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
        assert_eq!(p_slots[0].slot, U256::ZERO);
        assert_eq!(p_slots[1].slot, U256::ZERO);
        assert_eq!(p_slots[1].byte_offset, 20);
        let hits = detect_proxy_storage_collisions(
            &[(
                "BadProxy".into(),
                "contracts/Proxy.sol".into(),
                p_slots.clone(),
            )],
            &[(
                "ImplBad".into(),
                "contracts/Impl.sol".into(),
                i_slots.clone(),
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "SMG-WEB3-STORAGE");

        // Unrelated proxy/impl stems in separate files (`TokenAProxy` vs `StakingRewardsImpl`) must not collide
        let unrelated = detect_proxy_storage_collisions(
            &[
                (
                    "TokenAProxy".into(),
                    "contracts/TokenAProxy.sol".into(),
                    p_slots.clone(),
                ),
                (
                    "TokenBProxy".into(),
                    "contracts/TokenBProxy.sol".into(),
                    p_slots,
                ),
            ],
            &[(
                "StakingRewardsImpl".into(),
                "contracts/StakingRewardsImpl.sol".into(),
                i_slots,
            )],
        );
        assert!(unrelated.is_empty());

        // Multi-dimensional fixed array `uint256[2][3]` consumes 2 * 3 = 6 slots
        assert_eq!(parse_fixed_array_slots("uint256[2][3]"), Some(6));
        assert_eq!(parse_fixed_array_slots("uint128[4]"), Some(2));

        // Non-ASCII hex string in decode_hex_bytecode must not panic on UTF-8 boundary
        assert!(decode_hex_bytecode("0x€a").is_empty());
    }
}
