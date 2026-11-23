//! Phase 31A: RFC 9113 HTTP/2 Single-Packet Race Engine (`END_STREAM` Gate) &
//! DB State Snapshot Conservation-of-Value Diff Verifier (strictly loopback-only).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// RFC 9113 §3.5 HTTP/2 client connection preface.
pub const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// RFC 9113 Frame Types.
pub const H2_FRAME_DATA: u8 = 0x00;
pub const H2_FRAME_HEADERS: u8 = 0x01;
pub const H2_FRAME_SETTINGS: u8 = 0x04;

/// RFC 9113 Frame Flags.
pub const H2_FLAG_END_STREAM: u8 = 0x01;
pub const H2_FLAG_END_HEADERS: u8 = 0x04;

/// RFC 9113 default maximum HTTP/2 frame payload size (`SETTINGS_MAX_FRAME_SIZE`).
pub const H2_DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

/// Builds a wire-valid RFC 9113 §4.1 9-byte HTTP/2 frame header + payload.
/// Payload lengths exceeding 24-bit frame capacity (`0x00FF_FFFF`) are clamped safely.
pub fn build_h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let clamped_len = payload.len().min(0x00FF_FFFF);
    let len = clamped_len as u32;
    let sid = stream_id & 0x7FFF_FFFF;
    let mut out = Vec::with_capacity(9 + clamped_len);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&payload[..clamped_len]);
    out
}

/// Encodes an RFC 7541 §5.1 7-bit prefix non-Huffman string length (`H = 0`) followed by raw bytes.
fn push_hpack_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 127 {
        buf.push(len as u8); // H = 0 (bit 7 clear)
    } else {
        buf.push(0x7F); // H = 0, 7-bit prefix = 127
        let mut rem = len - 127;
        while rem >= 128 {
            buf.push(((rem & 0x7F) as u8) | 0x80);
            rem >>= 7;
        }
        buf.push(rem as u8);
    }
    buf.extend_from_slice(bytes);
}

/// Encodes a minimal literal-without-indexing HPACK header block (`:method`, `:path`, `:scheme`, `:authority`)
/// using valid RFC 7541 §5.1 7-bit prefix integers (safe for headers/paths >= 128 bytes).
pub fn encode_hpack_literal_headers(method: &str, path: &str, authority: &str) -> Vec<u8> {
    fn push_hdr(buf: &mut Vec<u8>, name: &str, val: &str) {
        buf.push(0x00); // Literal Header Field without Indexing — New Name
        push_hpack_string(buf, name);
        push_hpack_string(buf, val);
    }
    let mut block = Vec::new();
    push_hdr(&mut block, ":method", method);
    push_hdr(&mut block, ":path", path);
    push_hdr(&mut block, ":scheme", "http");
    push_hdr(&mut block, ":authority", authority);
    push_hdr(&mut block, "content-type", "application/json");
    block
}

/// Two-phase single-packet HTTP/2 burst buffers:
/// - `staged_prefix`: Preface + SETTINGS + all `N` streams' `HEADERS` + `DATA(body[..len-1])` (NO `END_STREAM`)
/// - `final_end_stream_burst`: Single coalesced buffer containing the final 1-byte `DATA(END_STREAM)` frame
///   for every stream `1, 3, ..., 2N-1`, designed to be flushed in ONE TCP packet!
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2SinglePacketBurst {
    pub stream_ids: Vec<u32>,
    pub staged_prefix: Vec<u8>,
    pub final_end_stream_burst: Vec<u8>,
}

/// Constructs an RFC 9113 single-packet race burst for `concurrency` simultaneous streams.
pub fn build_h2_single_packet_burst(
    method: &str,
    path: &str,
    authority: &str,
    body: &[u8],
    concurrency: usize,
) -> Result<H2SinglePacketBurst> {
    if concurrency == 0 || concurrency > 64 {
        bail!("HTTP/2 race concurrency must be between 1 and 64");
    }
    let effective_body = if body.is_empty() { b"{}" } else { body };
    let (prefix_body, final_byte) = effective_body.split_at(effective_body.len() - 1);
    let hpack = encode_hpack_literal_headers(method, path, authority);
    if hpack.len() > H2_DEFAULT_MAX_FRAME_SIZE {
        bail!(
            "HTTP/2 HPACK header block ({} bytes) exceeds default SETTINGS_MAX_FRAME_SIZE ({H2_DEFAULT_MAX_FRAME_SIZE})",
            hpack.len()
        );
    }
    if prefix_body.len() > H2_DEFAULT_MAX_FRAME_SIZE {
        bail!(
            "HTTP/2 DATA payload ({} bytes) exceeds default SETTINGS_MAX_FRAME_SIZE ({H2_DEFAULT_MAX_FRAME_SIZE})",
            prefix_body.len()
        );
    }

    let mut staged_prefix = Vec::new();
    staged_prefix.extend_from_slice(H2_CLIENT_PREFACE);
    staged_prefix.extend_from_slice(&build_h2_frame(H2_FRAME_SETTINGS, 0, 0, &[]));

    let mut final_end_stream_burst = Vec::new();
    let mut stream_ids = Vec::with_capacity(concurrency);

    for idx in 0..concurrency {
        let stream_id = (idx as u32) * 2 + 1; // RFC 9113 §5.1.1: client-initiated streams are odd
        stream_ids.push(stream_id);
        staged_prefix.extend_from_slice(&build_h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS,
            stream_id,
            &hpack,
        ));
        if !prefix_body.is_empty() {
            staged_prefix.extend_from_slice(&build_h2_frame(
                H2_FRAME_DATA,
                0,
                stream_id,
                prefix_body,
            ));
        }
        final_end_stream_burst.extend_from_slice(&build_h2_frame(
            H2_FRAME_DATA,
            H2_FLAG_END_STREAM,
            stream_id,
            final_byte,
        ));
    }

    Ok(H2SinglePacketBurst {
        stream_ids,
        staged_prefix,
        final_end_stream_burst,
    })
}

/// Dispatches an HTTP/2 single-packet race burst strictly against a loopback `SocketAddr`
/// (`127.0.0.1` / `::1`) with `TCP_NODELAY` so all `END_STREAM` frames flush in one TCP write.
pub fn execute_loopback_h2_single_packet_race(
    addr: SocketAddr,
    burst: &H2SinglePacketBurst,
    timeout: Duration,
) -> Result<usize> {
    let ip: IpAddr = addr.ip();
    if !ip.is_loopback() {
        bail!("Refusing HTTP/2 single-packet race against non-loopback address {addr}");
    }
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_nodelay(true)?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&burst.staged_prefix)?;
    stream.flush()?;
    std::thread::sleep(Duration::from_millis(5));
    stream.write_all(&burst.final_end_stream_burst)?;
    stream.flush()?;
    Ok(burst.stream_ids.len())
}

/// Pre-race or post-race database/ledger state snapshot for mathematical race proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbStateSnapshot {
    pub balances: BTreeMap<String, i64>,
    pub row_counts: BTreeMap<String, u64>,
}

impl DbStateSnapshot {
    pub fn total_balance(&self) -> i128 {
        self.balances.values().map(|&v| v as i128).sum()
    }
}

/// Result of comparing pre-race and post-race database snapshots against conservation invariants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbInvariantVerdict {
    pub violated: bool,
    pub negative_accounts: Vec<String>,
    pub expected_total_delta: i128,
    pub actual_total_delta: i128,
    pub extra_rows_inserted: u64,
    pub summary: String,
}

/// Proves double-spend, negative balance, or conservation-of-value violations by diffing
/// `before` and `after` database snapshots against `expected_net_delta` and `max_allowed_row_growth`.
pub fn diff_db_snapshots(
    before: &DbStateSnapshot,
    after: &DbStateSnapshot,
    expected_net_delta: i128,
    max_allowed_row_growth: u64,
) -> DbInvariantVerdict {
    let negative_accounts: Vec<String> = after
        .balances
        .iter()
        .filter(|&(_, &bal)| bal < 0)
        .map(|(acct, _)| acct.clone())
        .collect();

    let actual_total_delta = after.total_balance() - before.total_balance();
    let delta_violated = actual_total_delta != expected_net_delta;

    let mut extra_rows_inserted = 0u64;
    for (tbl, &after_cnt) in &after.row_counts {
        let before_cnt = before.row_counts.get(tbl).copied().unwrap_or(0);
        let growth = after_cnt.saturating_sub(before_cnt);
        if growth > max_allowed_row_growth {
            extra_rows_inserted =
                extra_rows_inserted.saturating_add(growth - max_allowed_row_growth);
        }
    }

    let violated = !negative_accounts.is_empty() || delta_violated || extra_rows_inserted > 0;
    let summary = if !violated {
        format!(
            "Conservation invariant held (delta={actual_total_delta}, negative_accounts=0, extra_rows=0)"
        )
    } else {
        format!(
            "RACE INVARIANT VIOLATED: expected_delta={expected_net_delta}, actual_delta={actual_total_delta}, negative_accounts={negative_accounts:?}, extra_rows={extra_rows_inserted}"
        )
    };

    DbInvariantVerdict {
        violated,
        negative_accounts,
        expected_total_delta: expected_net_delta,
        actual_total_delta,
        extra_rows_inserted,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    #[test]
    fn builds_and_dispatches_rfc9113_single_packet_h2_burst_on_loopback() {
        let burst = build_h2_single_packet_burst(
            "POST",
            "/api/v1/checkout/withdraw",
            "127.0.0.1:8080",
            br#"{"amount":100}"#,
            4,
        )
        .unwrap();
        assert_eq!(burst.stream_ids, vec![1, 3, 5, 7]);
        assert!(burst.staged_prefix.starts_with(H2_CLIENT_PREFACE));
        // Each final END_STREAM DATA frame is 9-byte header + 1-byte payload = 10 bytes * 4 streams = 40 bytes
        assert_eq!(burst.final_end_stream_burst.len(), 40);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_total = burst.staged_prefix.len() + burst.final_end_stream_burst.len();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).unwrap();
            buf.len()
        });

        let sent_streams =
            execute_loopback_h2_single_packet_race(addr, &burst, Duration::from_secs(2)).unwrap();
        assert_eq!(sent_streams, 4);
        assert_eq!(handle.join().unwrap(), expected_total);

        // Non-loopback host MUST be rejected fail-closed
        let remote: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(
            execute_loopback_h2_single_packet_race(remote, &burst, Duration::from_millis(100))
                .is_err()
        );

        // RFC 7541 7-bit HPACK integer encoding for paths >= 128 bytes must NOT set Huffman bit 0x80
        let long_path = format!("/api/{}", "a".repeat(150));
        let hpack = encode_hpack_literal_headers("GET", &long_path, "127.0.0.1:8080");
        // After `:method` (1+1+7+1+3=13 bytes), `:path` starts with 0x00, 0x05, ":path", 0x7F, (155-127)=28
        let path_marker = b":path";
        let pos = hpack
            .windows(path_marker.len())
            .position(|w| w == path_marker)
            .unwrap();
        assert_eq!(hpack[pos + 5], 0x7F);
        assert_eq!(hpack[pos + 6], (long_path.len() - 127) as u8);
    }

    #[test]
    fn db_snapshot_diff_proves_double_spend_and_accepts_atomic_tx() {
        let mut before = DbStateSnapshot::default();
        before.balances.insert("alice".into(), 100);
        before.row_counts.insert("withdrawals".into(), 0);

        // Double-spend race: two $100 withdrawals succeeded -> alice = -100, 2 rows inserted
        let mut after_race = DbStateSnapshot::default();
        after_race.balances.insert("alice".into(), -100);
        after_race.row_counts.insert("withdrawals".into(), 2);

        let race_verdict = diff_db_snapshots(&before, &after_race, -100, 1);
        assert!(race_verdict.violated);
        assert_eq!(race_verdict.negative_accounts, vec!["alice"]);
        assert_eq!(race_verdict.extra_rows_inserted, 1);

        // Properly locked single withdrawal -> alice = 0, 1 row inserted
        let mut after_safe = DbStateSnapshot::default();
        after_safe.balances.insert("alice".into(), 0);
        after_safe.row_counts.insert("withdrawals".into(), 1);

        let safe_verdict = diff_db_snapshots(&before, &after_safe, -100, 1);
        assert!(!safe_verdict.violated);
    }
}
