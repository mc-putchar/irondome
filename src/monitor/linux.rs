use crate::entropy::EntropyTracker;
use crate::logger::{IronDomeLogger, LOG_PATH};
use crate::memory::{heap_usage_bytes, is_memory_pressure, rss_usage_bytes};
use crate::telemetry::TelemetryTracker;

use super::PlatformMonitor;

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io::{self, Error};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

#[repr(align(8))]
struct AlignedBuf([u8; 4096]);

pub struct LinuxMonitor {
    fd: i32,
    entropy_tracker: EntropyTracker,
    telemetry_tracker: TelemetryTracker,
    target_paths: Vec<PathBuf>,
    backup_root: PathBuf,
    quarantined: Arc<Mutex<HashSet<PathBuf>>>,
}

impl PlatformMonitor for LinuxMonitor {
    fn init(logger: &IronDomeLogger, target_paths: &[PathBuf]) -> Result<Self> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_UNLIMITED_MARKS,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            logger.system_error("failed to initialize filesystem watch");
            return Err(anyhow!(Error::last_os_error()));
        }

        let mut entropy_tracker = EntropyTracker::new();
        let telemetry_tracker = TelemetryTracker::new();

        let flags = libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT;
        let mask: u64 = libc::FAN_ACCESS | libc::FAN_CLOSE_WRITE | libc::FAN_MODIFY;

        for target_path in target_paths {
            if let Err(e) = watch_path(logger, fd, target_path, flags, mask) {
                logger.system_warn(&format!("could not watch path {:?}: {}", target_path, e));

                if target_path.is_dir() {
                    for entry in WalkDir::new(target_path) {
                        match entry {
                            Ok(entry) => {
                                if entry.file_type().is_file() {
                                    entropy_tracker.seed_file(entry.into_path());
                                }
                            }
                            Err(e) => logger
                                .system_warn(&format!("could not access directory entry: {e}")),
                        }
                    }
                } else if target_path.is_file() {
                    entropy_tracker.seed_file(target_path.clone());
                }
            }
        }

        logger.system_info("baseline entropy indexing completed.");

        Ok(LinuxMonitor {
            fd,
            target_paths: target_paths.to_vec(),
            entropy_tracker,
            telemetry_tracker,
        })
    }

    fn poll_events(&mut self, logger: &IronDomeLogger) -> Result<()> {
        let mut buf = AlignedBuf([0_u8; 4096]);
        let meta_size = size_of::<libc::fanotify_event_metadata>();

        let len = unsafe {
            libc::read(
                self.fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len < 0 {
            let err = Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            logger.system_error(&format!("failed to read fanotify fd: {}", err));
            return Err(anyhow!("failed to read fanotify fd: {}", err));
        }

        let mut offset = 0_usize;
        let total = len as usize;

        while offset + meta_size <= total {
            let meta =
                unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                logger.system_error("Mismatched fanotify metadata version");
                break;
            }
            if meta.event_len as usize == 0_usize {
                break;
            }

            if (meta.mask & libc::FAN_Q_OVERFLOW) != 0 {
                logger.system_warn("fanotify queue overflowed!");
            }

            if meta.fd >= 0 {
                self.handle_event(logger, meta.fd, meta.pid, meta.mask);
                unsafe { libc::close(meta.fd) };
            }

            offset += meta.event_len as usize;
        }

        if is_memory_pressure() {
            let heap_mb = heap_usage_bytes() / (1024 * 1024);
            let rss_mb = rss_usage_bytes() / (1024 * 1024);
            logger.system_warn(&format!(
                "Memory pressure detected (heap: {} MB, rss: {} MB). Reclaiming caches",
                heap_mb, rss_mb
            ));
            self.entropy_tracker.reclaim_memory();
            self.telemetry_tracker.reclaim_memory();
        }

        Ok(())
    }
}

impl LinuxMonitor {
    fn is_monitored_path(&self, path: &Path) -> bool {
        if path == Path::new(LOG_PATH) || path.starts_with(&self.backup_root) {
            return false;
        }
        self.target_paths
            .iter()
            .any(|target| path.starts_with(target))
    }

    fn handle_event(&mut self, logger: &IronDomeLogger, fd: RawFd, pid: i32, mask: u64) {
        if pid as u32 == std::process::id() {
            return;
        }

        let proc_fd_path = format!("/proc/self/fd/{}", fd);
        let Ok(real_path) = fs::read_link(&proc_fd_path) else {
            return;
        };

        if !self.is_monitored_path(&real_path) {
            return;
        }

        if (mask & libc::FAN_ACCESS) != 0 {
            self.telemetry_tracker
                .on_file_access(logger, pid, &real_path);
        }

        if (mask & libc::FAN_CLOSE_WRITE) != 0 {
            let entropy_alert = match self.entropy_tracker.evaluate_fd(&real_path, fd) {
                Ok(Some(alert)) => {
                    if let Ok(mut q) = self.quarantined.lock() {
                        q.insert(real_path.clone());
                    }

                    let msg = match alert.old_entropy {
                        Some(old) => format!(
                            "PID {} modified {:?}: entropy change from {:.2} to {:.2} (delta: {:.2} bits/byte)",
                            pid, alert.path, old, alert.new_entropy, alert.delta
                        ),
                        None => format!(
                            "PID {} wrote high entropy file {:?}: {:.2} bits/byte",
                            pid, alert.path, alert.new_entropy
                        ),
                    };
                    logger.alert("ENTROPY", &msg);
                    Some(alert)
                }
                Ok(None) => None,
                Err(e) => {
                    logger.system_warn(&format!(
                        "failed to compute entropy for {:?}: {}",
                        real_path, e
                    ));
                    None
                }
            };

            self.telemetry_tracker
                .on_file_write(logger, pid, &real_path, entropy_alert.as_ref());
        } else if (mask & libc::FAN_MODIFY) != 0 {
            self.telemetry_tracker
                .on_file_write(logger, pid, &real_path, None);
        }
    }
}

impl Drop for LinuxMonitor {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn watch_path(
    logger: &IronDomeLogger,
    fd: i32,
    target_path: &Path,
    flags: u32,
    mask: u64,
) -> Result<()> {
    let c_path = CString::new(target_path.as_os_str().as_bytes())?;

    let ret = unsafe { libc::fanotify_mark(fd, flags, mask, libc::AT_FDCWD, c_path.as_ptr()) };
    if ret == -1 {
        let err = Error::last_os_error();
        logger.system_error(format!("failed to add watch on the path specified: {}", err).as_str());
        Err(anyhow!(err))
    } else {
        Ok(())
    }
}
