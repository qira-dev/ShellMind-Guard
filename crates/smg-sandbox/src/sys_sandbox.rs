//! Audited low-level OS syscall helpers isolated from the rest of `smg-sandbox`
//! (`Phase 4 / Q87`).

/// Queries whether a Unix process ID exists without sending a terminating signal.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn unix_pid_exists(raw_pid: libc::pid_t) -> bool {
    if raw_pid <= 0 {
        return false;
    }
    // SAFETY: `kill(pid, 0)` only queries signal deliverability for `raw_pid` and never
    // dereferences memory or modifies process state.
    let rc = unsafe { libc::kill(raw_pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}
