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
    #[inline]
    pub const fn width_mask(width_bits: u32) -> u64 {
        if width_bits == 0 || width_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << width_bits) - 1
        }
    }

    pub const fn constant(v: u64) -> Self {
        Self { value: v, mask: 0 }
    }

    pub const fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    pub const fn unknown_with_width(width_bits: u32) -> Self {
        Self {
            value: 0,
            mask: Self::width_mask(width_bits),
        }
    }

    #[inline]
    pub const fn masked(self, width_bits: u32) -> Self {
        let wm = Self::width_mask(width_bits);
        let m = self.mask & wm;
        let v = (self.value & wm) & !m;
        Self { value: v, mask: m }
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

    pub fn tnum_add_width(self, other: Self, width_bits: u32) -> Self {
        self.masked(width_bits)
            .tnum_add(other.masked(width_bits))
            .masked(width_bits)
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
    pub fn join(self, other: Self) -> Self {
        let width_bits = self.width_bits.max(other.width_bits);
        let mut out = Self {
            smin: self.smin.min(other.smin),
            smax: self.smax.max(other.smax),
            umin: self.umin.min(other.umin),
            umax: self.umax.max(other.umax),
            tnum: self.tnum.join(other.tnum).masked(width_bits),
            signed_wrap: self.signed_wrap || other.signed_wrap,
            width_bits,
        };
        out.reduce();
        out
    }

    pub fn constant_signed(val: i64, width_bits: u32) -> Self {
        let (sval, uval) = if width_bits == 32 {
            let v32 = val as i32;
            (v32 as i64, (v32 as u32) as u64)
        } else {
            (val, val as u64 & Tnum::width_mask(width_bits))
        };
        Self {
            smin: sval,
            smax: sval,
            umin: uval,
            umax: uval,
            tnum: Tnum::constant(uval).masked(width_bits),
            signed_wrap: false,
            width_bits,
        }
    }

    pub fn signed_range(smin: i64, smax: i64, width_bits: u32) -> Self {
        let (mut smin, mut smax) = if smin <= smax {
            (smin, smax)
        } else {
            (smax, smin)
        };
        if width_bits == 32 {
            smin = smin.clamp(i32::MIN as i64, i32::MAX as i64);
            smax = smax.clamp(i32::MIN as i64, i32::MAX as i64);
        }
        let max_w = Tnum::width_mask(width_bits);
        let mut out = if smin >= 0 {
            let umin = (smin as u64) & max_w;
            let umax = (smax as u64) & max_w;
            Self {
                smin,
                smax,
                umin,
                umax,
                tnum: Tnum::from_range(umin, umax).masked(width_bits),
                signed_wrap: false,
                width_bits,
            }
        } else {
            let min_neg_u = if width_bits == 32 {
                (smin as i32 as u32) as u64
            } else {
                (smin as u64) & max_w
            };
            let umax = if smax >= 0 {
                max_w
            } else if width_bits == 32 {
                (smax as i32 as u32) as u64
            } else {
                (smax as u64) & max_w
            };
            Self {
                smin,
                smax,
                umin: if smax >= 0 { 0 } else { min_neg_u },
                umax,
                tnum: if smax >= 0 {
                    Tnum::unknown_with_width(width_bits)
                } else {
                    Tnum::from_range(min_neg_u, umax).masked(width_bits)
                },
                signed_wrap: false,
                width_bits,
            }
        };
        out.reduce();
        out
    }

    pub fn from_u64_bounds(umin: u64, umax: u64, width_bits: u32) -> Self {
        let wmask = Tnum::width_mask(width_bits);
        let umin = umin & wmask;
        let umax = (umax & wmask).max(umin);
        let sign_bit = if width_bits == 32 {
            1u64 << 31
        } else if width_bits > 0 && width_bits < 64 {
            1u64 << (width_bits - 1)
        } else {
            1u64 << 63
        };
        let (smin, smax) = if umax < sign_bit {
            (umin as i64, umax as i64)
        } else if umin >= sign_bit {
            if width_bits == 32 {
                ((umin as u32 as i32) as i64, (umax as u32 as i32) as i64)
            } else {
                (umin as i64, umax as i64)
            }
        } else if width_bits == 32 {
            (i32::MIN as i64, i32::MAX as i64)
        } else {
            (i64::MIN, i64::MAX)
        };
        let mut s = Self {
            smin,
            smax,
            umin,
            umax,
            tnum: Tnum::from_range(umin, umax).masked(width_bits),
            signed_wrap: false,
            width_bits,
        };
        s.reduce();
        s
    }

    /// Reduced-product refinement `I_w ⋈ T_w` until fixed point.
    pub fn reduce(&mut self) {
        let wmask = Tnum::width_mask(self.width_bits);
        self.tnum = self.tnum.masked(self.width_bits);
        self.umin &= wmask;
        self.umax &= wmask;
        if self.umin > self.umax {
            // Normalize inverted/empty interval (e.g. conflicting guard tightening or width-mask wrap)
            // so `clamp(self.umin, self.umax)` can never panic.
            self.umax = self.umin;
        }

        for _ in 0..4 {
            let prev = (self.umin, self.umax, self.tnum);
            let tmin = self.tnum.min_u64();
            let tmax = self.tnum.max_u64();
            if tmin > self.umax || tmax < self.umin {
                // Disjoint interval and tnum: clamp to single witness point to preserve `umin <= umax`.
                let witness = tmin.clamp(self.umin, self.umax);
                self.umin = witness;
                self.umax = witness;
                self.tnum = Tnum::constant(witness).masked(self.width_bits);
                break;
            }
            self.umin = self.umin.max(tmin);
            self.umax = self.umax.min(tmax);
            if self.umin <= self.umax {
                let prefix_tnum = Tnum::from_range(self.umin, self.umax).masked(self.width_bits);
                let conflict =
                    (self.tnum.value ^ prefix_tnum.value) & !(self.tnum.mask | prefix_tnum.mask);
                if conflict != 0 {
                    // Known bits conflict between interval prefix and tnum; preserve valid range prefix.
                    self.tnum = prefix_tnum;
                    break;
                }
                let combined_mask = self.tnum.mask & prefix_tnum.mask;
                let combined_val = (self.tnum.value | prefix_tnum.value) & !combined_mask;
                self.tnum = Tnum {
                    value: combined_val,
                    mask: combined_mask,
                }
                .masked(self.width_bits);
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
        let width_bits = self.width_bits;
        let (min_limit, max_limit) = if width_bits == 32 {
            (i32::MIN as i128, i32::MAX as i128)
        } else {
            (i64::MIN as i128, i64::MAX as i128)
        };
        let lo = self.smin as i128 + rhs.smin as i128;
        let hi = self.smax as i128 + rhs.smax as i128;
        let wrapped = lo < min_limit || hi > max_limit;
        let sum_tnum = self.tnum.tnum_add_width(rhs.tnum, width_bits);
        if wrapped {
            let max_u = Tnum::width_mask(width_bits);
            let mut res = Self {
                smin: min_limit as i64,
                smax: max_limit as i64,
                umin: 0,
                umax: max_u,
                tnum: sum_tnum,
                signed_wrap: true,
                width_bits,
            };
            res.reduce();
            res
        } else {
            let mut res = Self::signed_range(lo as i64, hi as i64, width_bits);
            res.tnum = sum_tnum;
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

    fn add_diff_i128(&mut self, node_a: usize, node_b: usize, ci: i128) {
        if self.overflowed_pack_cap || node_a >= self.num_vars * 2 || node_b >= self.num_vars * 2 {
            return;
        }
        let p1 = self.idx(node_a, node_b);
        let p2 = self.idx(Self::bar(node_b), Self::bar(node_a));
        if ci < self.dbm[p1] {
            self.dbm[p1] = ci;
        }
        if ci < self.dbm[p2] {
            self.dbm[p2] = ci;
        }
    }

    /// Adds relational difference constraint `node_a - node_b <= c` while keeping coherent involution `M[b^][a^]`.
    pub fn add_diff(&mut self, node_a: usize, node_b: usize, c: i64) {
        self.add_diff_i128(node_a, node_b, c as i128);
    }

    /// Constrains `var_a + var_b <= c` (i.e. `v_a^+ - v_b^- <= c`).
    pub fn add_sum_le(&mut self, var_a: usize, var_b: usize, c: i64) {
        self.add_diff_i128(var_a * 2, var_b * 2 + 1, c as i128);
    }

    /// Constrains `var <= c` (`v^+ - v^- <= 2*c`) using wide `i128` scaling so `c > i64::MAX / 2` never saturates.
    pub fn add_upper_bound(&mut self, var: usize, c: i64) {
        self.add_diff_i128(var * 2, var * 2 + 1, (c as i128) * 2);
    }

    /// Constrains `var >= c` (`v^- - v^+ <= -2*c`) using wide `i128` negation & scaling so `i64::MIN` never saturates.
    pub fn add_lower_bound(&mut self, var: usize, c: i64) {
        self.add_diff_i128(var * 2 + 1, var * 2, -(c as i128) * 2);
    }

    /// Floyd-Warshall + Miné strong integer closure returning `false` on unsatisfiable negative cycle.
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
        // Step 1: Miné unary integer tightening: 2*v_i <= M[i][i^] ==> M[i][i^] = 2 * floor(M[i][i^] / 2)
        for i in 0..dim {
            let ii_bar = self.idx(i, Self::bar(i));
            if self.dbm[ii_bar] < Self::INF {
                self.dbm[ii_bar] = self.dbm[ii_bar].div_euclid(2) * 2;
            }
        }
        // Step 2: Miné binary tightening: M[i][j] = min(M[i][j], floor(M[i][i^]/2) + floor(M[j^][j]/2))
        for i in 0..dim {
            let m_ii_bar = self.dbm[self.idx(i, Self::bar(i))];
            if m_ii_bar >= Self::INF {
                continue;
            }
            let half_i = m_ii_bar.div_euclid(2);
            for j in 0..dim {
                let m_jbar_j = self.dbm[self.idx(Self::bar(j), j)];
                if m_jbar_j >= Self::INF {
                    continue;
                }
                let c_half = half_i.saturating_add(m_jbar_j.div_euclid(2));
                let ij = self.idx(i, j);
                if c_half < self.dbm[ij] {
                    self.dbm[ij] = c_half;
                }
            }
        }
        // Step 3: Check negative self-cycles after integer tightening (catches Z-unsatisfiable 2x <= 1 && -2x <= -1)
        for i in 0..dim {
            if self.dbm[self.idx(i, i)] < 0 {
                return false;
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
            i64::try_from(raw.div_euclid(2)).ok()
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
    fn wrapped_interval_32bit_signed_add_and_sign_boundaries_are_sound() {
        // Counterexample HW-01a: (-1) + 1 in 32-bit width must wrap tnum to 0, never umin = 2^32 > umax = 0
        let neg_one = WrappedInterval::constant_signed(-1, 32);
        let pos_one = WrappedInterval::constant_signed(1, 32);
        let zero = neg_one.signed_add(pos_one);
        assert_eq!(zero.smin, 0);
        assert_eq!(zero.smax, 0);
        assert_eq!(zero.umin, 0);
        assert_eq!(zero.umax, 0);
        assert_eq!(zero.tnum, Tnum::constant(0));

        // Counterexample HW-01b: 32-bit unsigned range [0x8000_0000, 0xFFFF_FFFF] is negative in i32
        let high_u32 = WrappedInterval::from_u64_bounds(0x8000_0000, 0xFFFF_FFFF, 32);
        assert_eq!(high_u32.smin, i32::MIN as i64);
        assert_eq!(high_u32.smax, -1);
        assert!(high_u32.can_wrap_negative_to_large_size());

        // Counterexample HW-01c: 64-bit full unsigned range [0, u64::MAX] spans i64::MIN..=i64::MAX
        let full_u64 = WrappedInterval::from_u64_bounds(0, u64::MAX, 64);
        assert_eq!(full_u64.smin, i64::MIN);
        assert_eq!(full_u64.smax, i64::MAX);
    }

    #[test]
    fn sparse_octagon_proves_dma_bounds_and_tightens_integers_without_overflow() {
        // off (0) <= 64, len (1) <= 128 -> off + len <= 192 <= cap (256)
        let mut oct = SparseOctagon::new(2);
        oct.add_upper_bound(0, 64);
        oct.add_upper_bound(1, 128);
        assert!(oct.close());
        assert!(oct.proves_sum_le(0, 1, 256));
        assert!(!oct.proves_sum_le(0, 1, 160));

        // Counterexample HW-02a: large bound x <= 2^62 must not saturate i64::MAX and falsely prove 2x <= i64::MAX
        let mut large_oct = SparseOctagon::new(1);
        let big = 1i64 << 62;
        large_oct.add_upper_bound(0, big);
        assert!(large_oct.close());
        assert_eq!(large_oct.upper_bound(0), Some(big));
        assert!(!large_oct.proves_sum_le(0, 0, i64::MAX));

        // Counterexample HW-02b: Z-unsatisfiable system 2x <= 1 && -2x <= -1 (x in [0.5, 0.5]) must return false on close()
        let mut z_unsat = SparseOctagon::new(1);
        z_unsat.add_diff(0, 1, 1); // 2x <= 1
        z_unsat.add_diff(1, 0, -1); // -2x <= -1
        assert!(!z_unsat.close());

        // Beyond MAX_OCTAGON_VARS=12 degrades safely without blowup
        let capped = SparseOctagon::new(MAX_OCTAGON_VARS + 1);
        assert!(capped.overflowed_pack_cap);
    }

    #[test]
    fn inverted_interval_reduce_never_panics() {
        let mut s = WrappedInterval {
            smin: 60,
            smax: 59,
            umin: 60,
            umax: 59,
            tnum: Tnum::constant(0),
            signed_wrap: false,
            width_bits: 32,
        };
        s.reduce();
        assert!(s.umin <= s.umax);
    }
}
