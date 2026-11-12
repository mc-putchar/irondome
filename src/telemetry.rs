use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{entropy::EntropyAlert, logger::IronDomeLogger};

const MAX_TRACKED_PIDS: usize = 1024;
const SAMPLE_WINDOW: Duration = Duration::from_millis(250);
const ALERT_COOLDOWN: Duration = Duration::from_secs(3);

const READ_BYTES_PER_SEC_THRESHOLD: u64 = 10 * 1024 * 1024;
const READ_SYSCALLS_PER_SEC_THRESHOLD: u64 = 1000;
const CUMULATIVE_FIRST_READ_THRESHOLD: u64 = 25 * 1024 * 1024;
const PID_ACCESS_COUNT_THRESHOLD: u32 = 35;

const GLOBAL_BURST_WINDOW: Duration = Duration::from_secs(2);
const GLOBAL_READ_BURST_THRESHOLD: u32 = 60;
const GLOBAL_CRYPTO_BURST_THRESHOLD: u32 = 2;

const KNOWN_CRYPTO_LIBS: &[&str] = &[
    "libcrypto.so",
    "libsodium.so",
    "libgcrypt.so",
    "libnettle.so",
    "libgnutls.so",
];

const KNOWN_CRYPTO_BINS: &[&str] = &[
    "openssl",
    "gpg",
    "gpg2",
    "ccrypt",
    "mcrypt",
    "7z",
    "7za",
    "cryptsetup",
];

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcIoStats {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct CryptoSignature {
    pub comm: String,
    pub indicator: String,
}

pub struct PidState {
    pub comm: String,
    pub last_io: ProcIoStats,
    pub last_cpu_ticks: u64,
    pub last_sampled: Instant,
    pub access_events: u32,
    pub write_events: u32,
    pub high_entropy_writes: u32,
    pub crypto_sig: Option<Option<CryptoSignature>>,
    pub last_read_alert: Option<Instant>,
    pub last_crypto_alert: Option<Instant>,
}

impl PidState {
    pub fn new(comm: String, io: ProcIoStats, cpu_ticks: u64, now: Instant) -> Self {
        Self {
            comm,
            last_io: io,
            last_cpu_ticks: cpu_ticks,
            last_sampled: now,
            access_events: 0,
            write_events: 0,
            high_entropy_writes: 0,
            crypto_sig: None,
            last_read_alert: None,
            last_crypto_alert: None,
        }
    }
}

pub struct TelemetryTracker {
    pids: HashMap<i32, PidState>,
    global_window_start: Instant,
    global_read_events: u32,
    global_high_entropy_writes: u32,
    last_global_read_alert: Option<Instant>,
    last_global_crypto_alert: Option<Instant>,
}

impl Default for TelemetryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryTracker {
    pub fn new() -> Self {
        Self {
            pids: HashMap::with_capacity(256),
            global_window_start: Instant::now(),
            global_read_events: 0,
            global_high_entropy_writes: 0,
            last_global_read_alert: None,
            last_global_crypto_alert: None,
        }
    }

    /// Invoked on `FAN_ACCESS` events
    pub fn on_file_access(&mut self, logger: &IronDomeLogger, pid: i32, path: &Path) {
        let now = Instant::now();
        self.rotate_global_window(now);
        self.global_read_events += 1;

        self.prune_if_needed();

        let current_io = read_proc_io(pid).unwrap_or_default();
        let current_cpu = read_proc_cpu_ticks(pid).unwrap_or(0);

        let is_new_pid = !self.pids.contains_key(&pid);
        let state = self.pids.entry(pid).or_insert_with(|| {
            let comm = read_proc_comm(pid);
            PidState::new(comm, current_io, current_cpu, now)
        });

        state.access_events += 1;

        if is_new_pid
            && current_io.rchar >= CUMULATIVE_FIRST_READ_THRESHOLD
            && can_alert(&state.last_read_alert, now)
        {
            state.last_read_alert = Some(now);
            self.last_global_read_alert = Some(now);
            let mb = current_io.rchar as f64 / (1024.0 * 1024.0);
            logger.alert(
                "DISK_READ_ABUSE",
                &format!(
                    "PID {} ({}) read {:.2} MB (syscr: {}) accessing {:?}",
                    pid, state.comm, mb, current_io.syscr, path
                ),
            );
            return;
        }

        let elapsed = now.duration_since(state.last_sampled);
        if elapsed >= SAMPLE_WINDOW {
            let secs = elapsed.as_secs_f64();
            let delta_rchar = current_io.rchar.saturating_sub(state.last_io.rchar);
            let delta_syscr = current_io.syscr.saturating_sub(state.last_io.syscr);

            let byte_rate = (delta_rchar as f64 / secs) as u64;
            let syscr_rate = (delta_syscr as f64 / secs) as u64;
            let access_burst = state.access_events;

            state.last_sampled = now;
            state.last_io = current_io;
            state.last_cpu_ticks = current_cpu;
            state.access_events = 0;

            if (byte_rate >= READ_BYTES_PER_SEC_THRESHOLD
                || syscr_rate >= READ_SYSCALLS_PER_SEC_THRESHOLD
                || access_burst >= PID_ACCESS_COUNT_THRESHOLD)
                && can_alert(&state.last_read_alert, now)
            {
                state.last_read_alert = Some(now);
                self.last_global_read_alert = Some(now);
                let mb_per_sec = byte_rate as f64 / (1024.0 * 1024.0);
                logger.alert(
                    "DISK_READ_ABUSE",
                    &format!(
                        "PID {} ({}) excessive read activity: {:.2} MB/s ({} syscr/s, {} files) on {:?}",
                        pid, state.comm, mb_per_sec, syscr_rate, access_burst, path
                    )
                );
                return;
            }
        }

        if self.global_read_events >= GLOBAL_READ_BURST_THRESHOLD
            && can_alert(&self.last_global_read_alert, now)
        {
            self.last_global_read_alert = Some(now);
            let comm = &state.comm;
            logger.alert(
                "DISK_READ_ABUSE",
                &format!(
                    "High-frequency read burst ({} file accesses in <2s), latest by PID {} ({}) on {:?}",
                    self.global_read_events, pid, comm, path
                )
            );
        }
    }

    /// Invoked on `FAN_CLOSE_WRITE` and `FAN_MODIFY` events
    pub fn on_file_write(
        &mut self,
        logger: &IronDomeLogger,
        pid: i32,
        path: &Path,
        entropy_alert: Option<&EntropyAlert>,
    ) {
        let now = Instant::now();
        self.rotate_global_window(now);
        self.prune_if_needed();

        let current_io = read_proc_io(pid).unwrap_or_default();
        let current_cpu = read_proc_cpu_ticks(pid).unwrap_or(0);

        let state = self.pids.entry(pid).or_insert_with(|| {
            let comm = read_proc_comm(pid);
            PidState::new(comm, current_io, current_cpu, now)
        });

        state.write_events += 1;
        if entropy_alert.is_some() {
            state.high_entropy_writes += 1;
            self.global_high_entropy_writes += 1;
        }

        let sig_opt = state
            .crypto_sig
            .get_or_insert_with(|| detect_crypto_signature(pid, &state.comm))
            .clone();

        if let Some(sig) = sig_opt {
            let intensive_writes = state.write_events >= 3 || current_io.wchar >= 64 * 1024;
            if (entropy_alert.is_some() || intensive_writes)
                && can_alert(&state.last_crypto_alert, now)
            {
                state.last_crypto_alert = Some(now);
                self.last_global_crypto_alert = Some(now);
                let entropy_info = match entropy_alert {
                    Some(a) => format!(" (entropy: {:.2} bits/byte)", a.new_entropy),
                    None => String::new(),
                };
                logger.alert(
                    "CRYPTO_ACTIVITY",
                    &format!(
                        "PID {} ({}) using {} wrote to {:?}{}",
                        pid, sig.comm, sig.indicator, path, entropy_info
                    ),
                );
                return;
            }
        }

        let cpu_delta = current_cpu.saturating_sub(state.last_cpu_ticks);
        state.last_cpu_ticks = current_cpu;
        state.last_io = current_io;

        if let Some(alert) = entropy_alert {
            let behavioral_crypto = state.high_entropy_writes >= 2
                || self.global_high_entropy_writes >= GLOBAL_CRYPTO_BURST_THRESHOLD
                || cpu_delta > 0
                || current_cpu >= 2;

            if behavioral_crypto
                && can_alert(&state.last_crypto_alert, now)
                && can_alert(&self.last_global_crypto_alert, now)
            {
                state.last_crypto_alert = Some(now);
                self.last_global_crypto_alert = Some(now);
                logger.alert(
                    "CRYPTO_ACTIVITY",
                    &format!(
                        "Intensive encryption behavior by PID {} ({}) on {:?} (entropy {:.2} bits/byte, {} high-entropy writes)",
                        pid, state.comm, path, alert.new_entropy, state.high_entropy_writes.max(self.global_high_entropy_writes)
                    )
                );
            }
        }
    }

    fn rotate_global_window(&mut self, now: Instant) {
        if now.duration_since(self.global_window_start) >= GLOBAL_BURST_WINDOW {
            self.global_window_start = now;
            self.global_read_events = 0;
            self.global_high_entropy_writes = 0;
        }
    }

    fn prune_if_needed(&mut self) {
        if self.pids.len() >= MAX_TRACKED_PIDS {
            self.pids
                .retain(|pid, _| Path::new(&format!("/proc/{}", pid)).exists());
            if self.pids.len() >= MAX_TRACKED_PIDS {
                self.reclaim_memory();
            }
        }
    }

    pub fn reclaim_memory(&mut self) {
        self.pids.clear();
        self.pids.shrink_to(256);
    }
}

fn can_alert(last_alert: &Option<Instant>, now: Instant) -> bool {
    match last_alert {
        Some(prev) => now.duration_since(*prev) >= ALERT_COOLDOWN,
        None => true,
    }
}

fn read_proc_io(pid: i32) -> Option<ProcIoStats> {
    let mut buf = [0_u8; 512];
    let mut file = File::open(format!("/proc/{}/io", pid)).ok()?;
    let n = file.read(&mut buf).ok()?;
    let text = std::str::from_utf8(&buf[..n]).ok()?;

    let mut stats = ProcIoStats::default();

    for line in text.lines() {
        if let Some((key, val_str)) = line.split_once(':') {
            let val = val_str.trim().parse::<u64>().unwrap_or(0);
            match key.trim() {
                "rchar" => stats.rchar = val,
                "wchar" => stats.wchar = val,
                "syscr" => stats.syscr = val,
                "syscw" => stats.syscw = val,
                "read_bytes" => stats.read_bytes = val,
                "write_bytes" => stats.write_bytes = val,
                _ => {}
            }
        }
    }
    Some(stats)
}

fn read_proc_cpu_ticks(pid: i32) -> Option<u64> {
    let mut buf = [0_u8; 512];
    let mut file = File::open(format!("/proc/{}/stat", pid)).ok()?;
    let n = file.read(&mut buf).ok()?;
    let content = std::str::from_utf8(&buf[..n]).ok()?;

    let rest = content.rfind(')').map(|idx| &content[idx + 2..])?;
    let mut fields = rest.split_whitespace();

    let utime = fields.nth(11)?.parse::<u64>().ok()?;
    let stime = fields.next()?.parse::<u64>().ok()?;

    Some(utime.saturating_add(stime))
}

fn read_proc_comm(pid: i32) -> String {
    let mut buf = [0_u8; 64];
    if let Ok(mut file) = File::open(format!("/proc/{}/comm", pid))
        && let Ok(n) = file.read(&mut buf)
        && let Ok(s) = std::str::from_utf8(&buf[..n])
    {
        return s.trim().to_string();
    }

    String::from("unknown")
}

/// Inspects binary name, command line, and `/proc/[pid]/maps` for cryptographic indicators
fn detect_crypto_signature(pid: i32, comm: &str) -> Option<CryptoSignature> {
    for &bin in KNOWN_CRYPTO_BINS {
        if comm.eq_ignore_ascii_case(bin) || comm.contains(bin) {
            return Some(CryptoSignature {
                comm: comm.to_string(),
                indicator: format!("binary:{}", bin),
            });
        }
    }

    let mut cmd_buf = [0_u8; 512];
    if let Ok(mut file) = File::open(format!("/proc/{}/cmdline", pid))
        && let Ok(n) = file.read(&mut cmd_buf)
    {
        for b in &mut cmd_buf[..n] {
            if *b == 0 {
                *b = b' ';
            }
        }
        if let Ok(cmdline) = std::str::from_utf8(&cmd_buf[..n]) {
            for &bin in KNOWN_CRYPTO_BINS {
                if cmdline.contains(bin) {
                    return Some(CryptoSignature {
                        comm: comm.to_string(),
                        indicator: format!("cmdline:{}", bin),
                    });
                }
            }
        }
    }

    let maps_file = File::open(format!("/proc/{}/maps", pid)).ok()?;
    let mut reader = BufReader::with_capacity(4096, maps_file);
    let mut line = String::with_capacity(256);

    while reader.read_line(&mut line).ok()? > 0 {
        if let Some(pathname) = line.split_whitespace().nth(5) {
            for &lib in KNOWN_CRYPTO_LIBS {
                if pathname.contains(lib) {
                    return Some(CryptoSignature {
                        comm: comm.to_string(),
                        indicator: format!("library:{}", lib),
                    });
                }
            }
        }
        line.clear();
    }

    None
}
