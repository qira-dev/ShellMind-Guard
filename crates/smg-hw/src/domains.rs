/// Strict variable-cluster bound for `SparseOctagon` ($k \le 12 \implies 2k \le 24$ signed vertices).
pub const MAX_OCTAGON_VARS: usize = 12;

/// Linux-eBPF-style Tristate Known-Bits (`tnum`) domain: pair `(value, mask)` satisfying `value & mask == 0`.
/// Bit `j` of `mask` is `1` iff bit `j` is unknown; else fixed `0`/`1` in `value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

impl Tnum {
    pub const fn constant(v: u64) -> Self {
        Self { value: v, mask: 0 }
    }

    pub const fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    pub fn from_range(umin: u64, umax: u64) -> Self {
        if umin >= umax {
            return Self::constant(umin);
        }
        let chi = umin ^ umax;
        let bits = 64 - chi.leading_zeros();
        let mask = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        Self {
            value: umin & !mask,
            mask,
        }
    }

    pub fn join(self, other: Self) -> Self {
        let m = self.mask | other.mask | (self.value ^ other.value);
        let v = (self.value & other.value) & !m;
        Self { value: v, mask: m }
    }

    pub fn tnum_and(self, other: Self) -> Self {
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        Self {
            value: v,
            mask: alpha & beta & !v,
        }
    }

    pub fn tnum_or(self, other: Self) -> Self {
        let v = self.value | other.value;
        let m = self.mask | other.mask;
        Self {
            value: v,
            mask: m & !v,
        }
    }

    pub fn tnum_lshift(self, shift: u32) -> Self {
        if shift >= 64 {
            return Self::constant(0);
        }
        Self {
            value: self.value.wrapping_shl(shift),
            mask: self.mask.wrapping_shl(shift),
        }
    }

    pub fn tnum_rshift(self, shift: u32) -> Self {
        if shift >= 64 {
            return Self::constant(0);
        }
        Self {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    pub fn tnum_add(self, other: Self) -> Self {
        let sm = self.mask.wrapping_add(other.mask);
        let sv = self.value.wrapping_add(other.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Self {
            value: sv & !mu,
            mask: mu,
        }
    }

    pub fn min_u64(self) -> u64 {
        self.value
    }

    pub fn max_u64(self) -> u64 {
        self.value | self.mask
    }
}

/// Dual wrapped signed + unsigned interval domain `I_w` with `tnum` reduced-product tightening (`I_w ⋈ T_w`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrappedInterval {
    pub smin: i64,
    pub smax: i64,
    pub umin: u64,
    pub umax: u64,
    pub tnum: Tnum,
    pub signed_wrap: bool,
    pub width_bits: u32,
}

impl WrappedInterval {
    pub fn constant_signed(val: i64, width_bits: u32) -> Self {
        let uval = if width_bits == 32 {
            (val as i32 as u32) as u64
        } else {
            val as u64
        };
        Self {
            smin: val,
            smax: val,
            umin: uval,
            umax: uval,
            tnum: Tnum::constant(uval),
            signed_wrap: false,
            width_bits,
        }
    }

    pub fn signed_range(smin: i64, smax: i64, width_bits: u32) -> Self {
        let mut out = if smin >= 0 {
            let umin = smin as u64;
            let umax = smax as u64;
            Self {
                smin,
                smax,
                umin,
                umax,
                tnum: Tnum::from_range(umin, umax),
                signed_wrap: false,
                width_bits,
            }
        } else {
            let max_w = if width_bits == 32 {
                u32::MAX as u64
            } else {
                u64::MAX
            };
            let min_neg_u = if width_bits == 32 {
                (smin as i32 as u32) as u64
            } else {
                smin as u64
            };
            let umax = if smax >= 0 {
                max_w
            } else if width_bits == 32 {
                (smax as i32 as u32) as u64
            } else {
                smax as u64
            };
            Self {
                smin,
                smax,
                umin: if smax >= 0 { 0 } else { min_neg_u },
                umax,
                tnum: if smax >= 0 {
                    Tnum::unknown()
                } else {
                    Tnum::from_range(min_neg_u, umax)
                },
                signed_wrap: false,
                width_bits,
            }
        };
        out.reduce();
        out
    }

    pub fn from_u64_bounds(umin: u64, umax: u64, width_bits: u32) -> Self {
        let mut s = Self {
            smin: 0,
            smax: i64::MAX,
            umin,
            umax,
            tnum: Tnum::from_range(umin, umax),
            signed_wrap: false,
            width_bits,
        };
        if umax <= i64::MAX as u64 {
            s.smin = umin as i64;
            s.smax = umax as i64;
        }
        s.reduce();
        s
    }

    /// Reduced-product refinement `I_w ⋈ T_w` until fixed point.
    pub fn reduce(&mut self) {
        for _ in 0..4 {
            let prev = (self.umin, self.umax, self.tnum);
            self.umin = self.umin.max(self.tnum.min_u64());
            self.umax = self.umax.min(self.tnum.max_u64());
            if self.umin <= self.umax {
                let prefix_tnum = Tnum::from_range(self.umin, self.umax);
                let combined_mask = self.tnum.mask & prefix_tnum.mask;
                let combined_val = (self.tnum.value | prefix_tnum.value) & !combined_mask;
                self.tnum = Tnum {
                    value: combined_val,
                    mask: combined_mask,
                };
            }
            if (self.umin, self.umax, self.tnum) == prev {
                break;
            }
        }
    }

    pub fn can_wrap_negative_to_large_size(&self) -> bool {
        let high_bit_threshold = if self.width_bits == 32 {
            1u64 << 31
        } else {
            1u64 << 63
        };
        self.smin < 0 && self.umax >= high_bit_threshold
    }

    pub fn signed_add(self, rhs: Self) -> Self {
        let (min_limit, max_limit) = if self.width_bits == 32 {
            (i32::MIN as i128, i32::MAX as i128)
        } else {
            (i64::MIN as i128, i64::MAX as i128)
        };
        let lo = self.smin as i128 + rhs.smin as i128;
        let hi = self.smax as i128 + rhs.smax as i128;
        let wrapped = lo < min_limit || hi > max_limit;
        if wrapped {
            let max_u = if self.width_bits == 32 {
                u32::MAX as u64
            } else {
                u64::MAX
            };
            Self {
                smin: min_limit as i64,
                smax: max_limit as i64,
                umin: 0,
                umax: max_u,
                tnum: self.tnum.tnum_add(rhs.tnum),
                signed_wrap: true,
                width_bits: self.width_bits,
            }
        } else {
            let mut res = Self::signed_range(lo as i64, hi as i64, self.width_bits);
            res.tnum = self.tnum.tnum_add(rhs.tnum);
            res.reduce();
            res
        }
    }
}

/// Difference-Bound Matrix Octagon (`v_i^+ = 2i`, `v_i^- = 2i + 1`) strictly capped at `k <= MAX_OCTAGON_VARS (12)`
/// ensuring <= (24)^3 = 13,824 saturated ops per block closure.
#[derive(Debug, Clone)]
pub struct SparseOctagon {
    pub num_vars: usize,
    dbm: Vec<i128>,
    pub overflowed_pack_cap: bool,
}

impl SparseOctagon {
    const INF: i128 = i128::MAX / 4;

    pub fn new(num_vars: usize) -> Self {
        if num_vars > MAX_OCTAGON_VARS {
            return Self {
                num_vars: 0,
                dbm: Vec::new(),
                overflowed_pack_cap: true,
            };
        }
        let dim = num_vars * 2;
        let mut dbm = vec![Self::INF; dim * dim];
        for i in 0..dim {
            dbm[i * dim + i] = 0;
        }
        Self {
            num_vars,
            dbm,
            overflowed_pack_cap: false,
        }
    }

    #[inline]
    fn idx(&self, a: usize, b: usize) -> usize {
        a * (self.num_vars * 2) + b
    }

    #[inline]
    fn bar(node: usize) -> usize {
        node ^ 1
    }

    /// Adds relational difference constraint `node_a - node_b <= c` while keeping coherent involution `M[b^][a^]`.
    pub fn add_diff(&mut self, node_a: usize, node_b: usize, c: i64) {
        if self.overflowed_pack_cap || node_a >= self.num_vars * 2 || node_b >= self.num_vars * 2 {
            return;
        }
        let ci = c as i128;
        let p1 = self.idx(node_a, node_b);
        let p2 = self.idx(Self::bar(node_b), Self::bar(node_a));
        if ci < self.dbm[p1] {
            self.dbm[p1] = ci;
        }
        if ci < self.dbm[p2] {
            self.dbm[p2] = ci;
        }
    }

    /// Constrains `var_a + var_b <= c` (i.e. `v_a^+ - v_b^- <= c`).
    pub fn add_sum_le(&mut self, var_a: usize, var_b: usize, c: i64) {
        self.add_diff(var_a * 2, var_b * 2 + 1, c);
    }

    /// Constrains `var <= c` (`v^+ - v^- <= 2*c`).
    pub fn add_upper_bound(&mut self, var: usize, c: i64) {
        self.add_diff(var * 2, var * 2 + 1, c.saturating_mul(2));
    }

    /// Constrains `var >= c` (`v^- - v^+ <= -2*c`).
    pub fn add_lower_bound(&mut self, var: usize, c: i64) {
        self.add_diff(var * 2 + 1, var * 2, c.saturating_neg().saturating_mul(2));
    }

    /// Floyd-Warshall + Miné strong closure returning `false` on unsatisfiable negative cycle.
    pub fn close(&mut self) -> bool {
        if self.overflowed_pack_cap {
            return true;
        }
        let dim = self.num_vars * 2;
        for k in 0..dim {
            for i in 0..dim {
                let ik = self.dbm[self.idx(i, k)];
                if ik >= Self::INF {
                    continue;
                }
                for j in 0..dim {
                    let kj = self.dbm[self.idx(k, j)];
                    if kj >= Self::INF {
                        continue;
                    }
                    let cand = ik.saturating_add(kj);
                    let ij = self.idx(i, j);
                    if cand < self.dbm[ij] {
                        self.dbm[ij] = cand;
                    }
                }
            }
        }
        // Miné tightening: M[i][j] = min(M[i][j], floor((M[i][i^] + M[j^][j]) / 2))
        for i in 0..dim {
            if self.dbm[self.idx(i, i)] < 0 {
                return false;
            }
            for j in 0..dim {
                let c_half = (self.dbm[self.idx(i, Self::bar(i))]
                    .saturating_add(self.dbm[self.idx(Self::bar(j), j)]))
                    / 2;
                let ij = self.idx(i, j);
                if c_half < self.dbm[ij] {
                    self.dbm[ij] = c_half;
                }
            }
        }
        true
    }

    pub fn upper_bound(&self, var: usize) -> Option<i64> {
        if self.overflowed_pack_cap || var >= self.num_vars {
            return None;
        }
        let raw = self.dbm[self.idx(var * 2, var * 2 + 1)];
        if raw >= Self::INF / 2 {
            None
        } else {
            Some((raw / 2) as i64)
        }
    }

    pub fn proves_sum_le(&self, var_a: usize, var_b: usize, limit: i64) -> bool {
        if self.overflowed_pack_cap || var_a >= self.num_vars || var_b >= self.num_vars {
            return false;
        }
        self.dbm[self.idx(var_a * 2, var_b * 2 + 1)] <= limit as i128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnum_and_wrapped_interval_reduced_product() {
        let a = Tnum::from_range(0, 15); // lower 4 bits unknown -> 0..15
        let aligned = a.tnum_and(Tnum::constant(0xFFFC));
        assert_eq!(aligned.min_u64(), 0);
        assert_eq!(aligned.max_u64(), 12);

        let sum = Tnum::constant(8).tnum_add(Tnum::from_range(0, 3));
        assert_eq!(sum.min_u64(), 8);
        assert_eq!(sum.max_u64(), 11);

        // Signed negative len passed to size_t wraps >= 2^31
        let signed_neg = WrappedInterval::signed_range(-1, 64, 32);
        assert!(signed_neg.can_wrap_negative_to_large_size());

        let guarded = WrappedInterval::signed_range(0, 64, 32);
        assert!(!guarded.can_wrap_negative_to_large_size());
    }

    #[test]
    fn sparse_octagon_proves_dma_bounds_under_cap() {
        // off (0) <= 64, len (1) <= 128 -> off + len <= 192 <= cap (256)
        let mut oct = SparseOctagon::new(2);
        oct.add_upper_bound(0, 64);
        oct.add_upper_bound(1, 128);
        assert!(oct.close());
        assert!(oct.proves_sum_le(0, 1, 256));
        assert!(!oct.proves_sum_le(0, 1, 160));

        // Beyond MAX_OCTAGON_VARS=12 degrades safely without blowup
        let capped = SparseOctagon::new(MAX_OCTAGON_VARS + 1);
        assert!(capped.overflowed_pack_cap);
    }
}
