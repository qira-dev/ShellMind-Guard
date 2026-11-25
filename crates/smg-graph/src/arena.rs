use crate::ast::GuardKind;
use std::collections::{HashMap, HashSet};

/// Compact 32-bit interned identifier indexing symbols, file paths, and scoped names inside [`SymbolArena`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolId(pub u32);

/// Memory budget bounds applied to [`SymbolArena`] so pathological monorepos cannot exhaust RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaBudget {
    pub max_strings: usize,
    pub max_bytes: usize,
}

impl Default for ArenaBudget {
    fn default() -> Self {
        Self {
            max_strings: 250_000,
            max_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Telemetry counters describing arena compression and memory-cap enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaStats {
    pub unique_symbols: usize,
    pub total_bytes: usize,
    pub budget_capped: bool,
}

/// Dense string interner replacing hot cloned `String` keys in lattice solving and cross-file BFS.
#[derive(Debug, Clone)]
pub struct SymbolArena {
    strings: Vec<String>,
    lookup: HashMap<String, SymbolId>,
    bytes_used: usize,
    budget: ArenaBudget,
    budget_capped: bool,
    overflow_counter: u32,
}

impl Default for SymbolArena {
    fn default() -> Self {
        Self::with_budget(ArenaBudget::default())
    }
}

impl SymbolArena {
    /// Creates an empty arena enforcing the supplied memory and cardinality cap.
    pub fn with_budget(budget: ArenaBudget) -> Self {
        let mut arena = Self {
            strings: Vec::with_capacity(256),
            lookup: HashMap::with_capacity(256),
            bytes_used: 0,
            budget,
            budget_capped: false,
            overflow_counter: 0,
        };
        // Reserve `SymbolId(0)` strictly as an uninternable invalid/overflow sentinel,
        // and intern `""` at `SymbolId(1)` (when budget permits) so root-level directories
        // (`go_parent_dir == ""`) receive a valid non-zero `SymbolId`.
        arena.strings.push(String::new());
        if arena.strings.len() < arena.budget.max_strings {
            let empty_id = SymbolId(arena.strings.len() as u32);
            arena.strings.push(String::new());
            arena.lookup.insert(String::new(), empty_id);
        }
        arena
    }

    /// Interns `value` to a deterministic [`SymbolId`]. Once the configured budget is exhausted,
    /// allocates distinct monotonic overflow IDs (`u32::MAX - overflow_counter`) without storing
    /// the string so two distinct uninterned symbols never collide as equal `SymbolId`s.
    pub fn intern(&mut self, value: &str) -> SymbolId {
        if let Some(&id) = self.lookup.get(value) {
            return id;
        }
        if self.strings.len() >= self.budget.max_strings
            || self.bytes_used.saturating_add(value.len()) > self.budget.max_bytes
        {
            self.budget_capped = true;
            let overflow_id = SymbolId(u32::MAX.saturating_sub(self.overflow_counter));
            self.overflow_counter = self.overflow_counter.saturating_add(1);
            return overflow_id;
        }
        let id = SymbolId(self.strings.len() as u32);
        let owned = value.to_string();
        self.bytes_used = self.bytes_used.saturating_add(owned.len());
        self.strings.push(owned.clone());
        self.lookup.insert(owned, id);
        id
    }

    /// Resolves an existing [`SymbolId`] back to its interned string slice without allocating.
    pub fn resolve(&self, id: SymbolId) -> &str {
        self.strings
            .get(id.0 as usize)
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Looks up a string without allocating or mutating the arena.
    pub fn get(&self, value: &str) -> Option<SymbolId> {
        self.lookup.get(value).copied()
    }

    pub fn stats(&self) -> ArenaStats {
        ArenaStats {
            unique_symbols: self.strings.len(),
            total_bytes: self.bytes_used,
            budget_capped: self.budget_capped,
        }
    }
}

/// Bit-packed 4-byte set of [`GuardKind`] replacing heap `HashSet` clones in lattice dataflow loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct GuardBitset(pub u32);

impl GuardBitset {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn bit_for(kind: GuardKind) -> u32 {
        match kind {
            GuardKind::Auth => 1 << 0,
            GuardKind::TxLock => 1 << 1,
            GuardKind::SqlSanitizer => 1 << 2,
            GuardKind::CmdSanitizer => 1 << 3,
            GuardKind::PathSanitizer => 1 << 4,
            GuardKind::SsrfSanitizer => 1 << 5,
            GuardKind::XssSanitizer => 1 << 6,
            GuardKind::CsrfProtection => 1 << 7,
            GuardKind::OwnershipCheck => 1 << 8,
            GuardKind::SecretPolicy => 1 << 9,
            GuardKind::ConfigPolicy => 1 << 10,
            GuardKind::DependencyPolicy => 1 << 11,
            GuardKind::FrontendContract => 1 << 12,
            GuardKind::LockOrdering => 1 << 13,
            GuardKind::ResourceCleanup => 1 << 14,
            GuardKind::MemoryBounds => 1 << 15,
            GuardKind::MobilePolicy => 1 << 16,
            GuardKind::InputValidation => 1 << 17,
        }
    }

    #[inline]
    pub const fn singleton(kind: GuardKind) -> Self {
        Self(Self::bit_for(kind))
    }

    #[inline]
    pub fn from_set(set: &HashSet<GuardKind>) -> Self {
        let mut bits = 0u32;
        for &g in set {
            bits |= Self::bit_for(g);
        }
        Self(bits)
    }

    #[inline]
    pub const fn insert(&mut self, kind: GuardKind) {
        self.0 |= Self::bit_for(kind);
    }

    #[inline]
    pub const fn contains(self, kind: GuardKind) -> bool {
        (self.0 & Self::bit_for(kind)) != 0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn to_set(self) -> HashSet<GuardKind> {
        const ALL: &[GuardKind] = &[
            GuardKind::Auth,
            GuardKind::TxLock,
            GuardKind::SqlSanitizer,
            GuardKind::CmdSanitizer,
            GuardKind::PathSanitizer,
            GuardKind::SsrfSanitizer,
            GuardKind::XssSanitizer,
            GuardKind::CsrfProtection,
            GuardKind::OwnershipCheck,
            GuardKind::SecretPolicy,
            GuardKind::ConfigPolicy,
            GuardKind::DependencyPolicy,
            GuardKind::FrontendContract,
            GuardKind::LockOrdering,
            GuardKind::ResourceCleanup,
            GuardKind::MemoryBounds,
            GuardKind::MobilePolicy,
            GuardKind::InputValidation,
        ];
        let mut out = HashSet::new();
        for &g in ALL {
            if self.contains(g) {
                out.insert(g);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_arena_deduplication_and_budget_cap() {
        let mut arena = SymbolArena::with_budget(ArenaBudget {
            max_strings: 4,
            max_bytes: 32,
        });
        let a1 = arena.intern("src/routes/billing.ts");
        let a2 = arena.intern("src/routes/billing.ts");
        assert_eq!(a1, a2);
        assert_eq!(arena.resolve(a1), "src/routes/billing.ts");

        // Next string fits (`max_strings=4`: sentinel + billing.ts + debit = 3 <= 4, bytes <= 32)
        let b1 = arena.intern("debit");
        assert_ne!(b1, SymbolId(0));

        // Exceeds remaining byte budget -> returns distinct monotonic overflow IDs resolving to ""
        let c1 = arena.intern("this_string_exceeds_32_bytes_limit_a");
        let c2 = arena.intern("this_string_exceeds_32_bytes_limit_b");
        assert_ne!(c1, c2);
        assert_eq!(arena.resolve(c1), "");
        assert_eq!(arena.resolve(c2), "");
        assert!(arena.stats().budget_capped);
    }

    #[test]
    fn test_guard_bitset_lattice_algebra() {
        let mut a = GuardBitset::EMPTY;
        a.insert(GuardKind::Auth);
        a.insert(GuardKind::TxLock);

        let b = GuardBitset::singleton(GuardKind::Auth);
        let meet = a.intersect(b);
        assert!(meet.contains(GuardKind::Auth));
        assert!(!meet.contains(GuardKind::TxLock));
        assert_eq!(meet.to_set().len(), 1);
    }
}
