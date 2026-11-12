use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

const MAX_BASELINE_ENTRIES: usize = 50_000;
const MAX_SAMPLE_BYTES: usize = 4 * 1024 * 1024;

const HIGH_ENTROPY_THRESHOLD: f64 = 7.80;
const ENTROPY_DELTA_THRESHOLD: f64 = 1.20;

#[derive(Debug, Clone)]
pub struct EntropyAlert {
    pub path: PathBuf,
    pub old_entropy: Option<f64>,
    pub new_entropy: f64,
    pub delta: f64,
}

pub struct EntropyTracker {
    baselines: HashMap<PathBuf, f64>,
}

impl Default for EntropyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyTracker {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::with_capacity(1024),
        }
    }

    pub fn seed_file(&mut self, path: PathBuf) {
        if self.baselines.len() >= MAX_BASELINE_ENTRIES {
            return;
        }
        if let Ok(file) = File::open(&path)
            && let Ok(entropy) = calculate_fd_entropy(file.as_raw_fd())
        {
            self.baselines.insert(path, entropy);
        }
    }

    pub fn evaluate_fd(&mut self, path: &Path, fd: RawFd) -> Result<Option<EntropyAlert>> {
        let new_entropy = calculate_fd_entropy(fd)?;

        if self.baselines.len() >= MAX_BASELINE_ENTRIES && !self.baselines.contains_key(path) {
            self.evict_stale_or_half();
        }

        let old_entropy = self.baselines.insert(path.to_path_buf(), new_entropy);

        match old_entropy {
            Some(old) => {
                if is_sus_entropy_change(old, new_entropy) {
                    return Ok(Some(EntropyAlert {
                        path: path.to_path_buf(),
                        old_entropy: Some(old),
                        new_entropy,
                        delta: new_entropy - old,
                    }));
                }
            }
            None => {
                // Check for newly created encrypted file
                if new_entropy >= HIGH_ENTROPY_THRESHOLD {
                    return Ok(Some(EntropyAlert {
                        path: path.to_path_buf(),
                        old_entropy: None,
                        new_entropy,
                        delta: new_entropy,
                    }));
                }
            }
        }

        Ok(None)
    }

    pub fn evict_stale_or_half(&mut self) {
        self.baselines.retain(|p, _| p.exists());
        if self.baselines.len() >= MAX_BASELINE_ENTRIES {
            let mut keep = false;
            self.baselines.retain(|_, _| {
                keep = !keep;
                keep
            });
        }
        self.baselines.shrink_to_fit();
    }

    pub fn reclaim_memory(&mut self) {
        self.baselines.clear();
        self.baselines.shrink_to(1024);
    }

    pub fn cached_count(&self) -> usize {
        self.baselines.len()
    }
}

/// Computes Shannon entropy (0.0 - 8.0 bits/byte) from a raw fd
/// Reads using pread up to MAX_SAMPLE_BYTES in 64 KB chunks
pub fn calculate_fd_entropy(fd: RawFd) -> Result<f64> {
    let mut frequency = [0_usize; 256];
    let mut total_bytes = 0_usize;
    let mut buf = [0_u8; 65536];

    while total_bytes < MAX_SAMPLE_BYTES {
        let to_read = buf.len().min(MAX_SAMPLE_BYTES - total_bytes);
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                to_read,
                total_bytes as libc::off_t,
            )
        };

        if n < 0 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!(err));
        }
        if n == 0 {
            break;
        }

        let bytes_read = n as usize;
        for &byte in &buf[..bytes_read] {
            frequency[byte as usize] += 1;
        }
        total_bytes += bytes_read;
    }

    Ok(entropy_from_freq(&frequency, total_bytes))
}

// keep for testing
#[allow(dead_code)]
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0_usize; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    entropy_from_freq(&frequency, data.len())
}

fn entropy_from_freq(frequency: &[usize; 256], total_bytes: usize) -> f64 {
    if total_bytes == 0 {
        return 0.0;
    }

    let mut entropy = 0.0_f64;
    let len_f64 = total_bytes as f64;

    for &count in frequency {
        if count > 0 {
            let probability = count as f64 / len_f64;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Evaluates if an entropy transition might indicate file encryption
///   Assumptions:
///     - encrypted files score > HIGH_ENTROPY_THRESHOLD bits/byte
///     - plain text files score 3.0 - 5.5
///   Change is flagged as suspicious if:
///     - there is a significant jump (ENTROPY_DELTA_THRESHOLD) towards high entropy zone
///     - the entropy changes to high entropy zone
pub fn is_sus_entropy_change(old: f64, new: f64) -> bool {
    let delta = new - old;

    delta >= ENTROPY_DELTA_THRESHOLD || (delta >= 0.6 && old < 7.2 && new >= HIGH_ENTROPY_THRESHOLD)
}
