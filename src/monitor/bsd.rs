use crate::entropy::EntropyTracker;
use crate::logger::{IronDomeLogger, LOG_PATH};
use crate::memory::{heap_usage_bytes, is_memory_pressure, rss_usage_bytes};
use crate::telemetry::TelemetryTracker;

use super::PlatformMonitor;

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Error};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::{fs, ptr};

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

const MAX_WATCHED_FDS: usize = 4096;

#[cfg(target_os = "freebsd")]
const VNODE_FFLAGS: u32 = libc::NOTE_WRITE
    | libc::NOTE_EXTEND
    | libc::NOTE_ATTRIB
    | libc::NOTE_DELETE
    | libc::NOTE_RENAME
    | libc::NOTE_LINK
    | libc::NOTE_REVOKE
    | libc::NOTE_READ
    | libc::NOTE_CLOSE_WRITE;

#[cfg(target_os = "macos")]
const VNODE_FFLAGS: u32 = libc::NOTE_WRITE
    | libc::NOTE_EXTEND
    | libc::NOTE_ATTRIB
    | libc::NOTE_DELETE
    | libc::NOTE_RENAME
    | libc::NOTE_LINK
    | libc::NOTE_REVOKE
    | libc::NOTE_FUNLOCK;

#[derive(Debug, Clone)]
struct WatchedNode {
    path: PathBuf,
    is_dir: bool,
    ino: u64,
    last_atime: i64,
    last_atime_nsec: i64,
}

pub struct BsdMonitor {
    kq: RawFd,
    fd_map: HashMap<RawFd, WatchedNode>,
    path_to_fd: HashMap<PathBuf, RawFd>,
    entropy_tracker: EntropyTracker,
    telemetry_tracker: TelemetryTracker,
}

impl PlatformMonitor for BsdMonitor {
    fn init(logger: &IronDomeLogger, target_paths: &[PathBuf]) -> Result<Self> {
        raise_fd_limit(logger);

        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            logger.system_error("failed to initialize kqueue");
            return Err(anyhow!(Error::last_os_error()));
        }
        unsafe {
            libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC);
        }

        let mut monitor = BsdMonitor {
            kq,
            fd_map: HashMap::with_capacity(512),
            path_to_fd: HashMap::with_capacity(512),
            entropy_tracker: EntropyTracker::new(),
            telemetry_tracker: TelemetryTracker::new(),
        };

        for target_path in target_paths {
            if target_path.is_dir() {
                for entry in WalkDir::new(target_path).follow_links(false) {
                    match entry {
                        Ok(entry) => {
                            let path = entry.into_path();
                            if path == Path::new(LOG_PATH) {
                                continue;
                            }
                            if path.is_dir() {
                                let _ = monitor.watch_node(logger, &path, true, false);
                            } else if path.is_file() {
                                monitor.entropy_tracker.seed_file(path.clone());
                                let _ = monitor.watch_node(logger, &path, false, false);
                            }
                        }
                        Err(e) => {
                            logger.system_warn(&format!("could not access directory entry: {e}"))
                        }
                    }
                }
            } else if target_path.is_file() {
                monitor.entropy_tracker.seed_file(target_path.clone());
                monitor.watch_node(logger, target_path, false, false)?;
            }
        }

        logger.system_info("BSD kqueue baseline entropy indexing completed.");
        Ok(monitor)
    }

    fn poll_events(&mut self, logger: &IronDomeLogger) -> Result<()> {
        let mut events: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 250_000_000,
        };

        let n_events = unsafe {
            libc::kevent(
                self.kq,
                ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                &timeout,
            )
        };

        if n_events < 0 {
            let err = Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            logger.system_error(&format!("kevent failed: {err}"));
            return Err(anyhow!("kevent wait failed: {err}"));
        }

        for ev in &events[..n_events as usize] {
            let fd = ev.ident as RawFd;
            let fflags = ev.fflags;
            self.handle_kevent(logger, fd, fflags);
        }

        self.poll_atime_reads(logger);

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

impl BsdMonitor {
    fn handle_kevent(&mut self, logger: &IronDomeLogger, fd: RawFd, fflags: u32) {
        let Some(node) = self.fd_map.get(&fd).cloned() else {
            return;
        };

        if node.is_dir {
            #[cfg(target_os = "freebsd")]
            if (fflags & (libc::NOTE_READ as u32)) != 0 {
                self.telemetry_tracker.on_file_access(logger, 0, &node.path);
            }

            let dir_changed = (fflags
                & (libc::NOTE_WRITE | libc::NOTE_EXTEND | libc::NOTE_LINK | libc::NOTE_RENAME))
                != 0;
            if dir_changed {
                self.sync_directory(logger, &node.path);
            }

            if (fflags & (libc::NOTE_DELETE | libc::NOTE_REVOKE)) != 0 {
                self.unwatch_fd(fd);
            }
            return;
        }

        #[cfg(target_os = "freebsd")]
        if (fflags & (libc::NOTE_READ as u32)) != 0 {
            self.telemetry_tracker.on_file_access(logger, 0, &node.path);
        }

        let was_modified = (fflags & (libc::NOTE_WRITE | libc::NOTE_EXTEND)) != 0;
        #[cfg(target_os = "freebsd")]
        let was_modified = was_modified || (fflags & (libc::NOTE_CLOSE_WRITE as u32)) != 0;

        if was_modified {
            self.evaluate_and_report_write(logger, &node.path, fd);
        }

        // If a file was unlinked or overwritten via `mv temp.enc file.txt`
        if (fflags & (libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE)) != 0 {
            self.unwatch_fd(fd);
            // If a replacement file now sits at `node.path`, watch and evaluate it immediately
            if node.path.is_file() {
                let _ = self.watch_node(logger, &node.path, false, true);
            }
        }
    }

    /// Walks a directory when `NOTE_WRITE` fires on it, registering any newly created
    /// subdirectories/files and detecting atomic inode replacements (`mv a.enc a.txt`).
    fn sync_directory(&mut self, logger: &IronDomeLogger, dir_path: &Path) {
        for entry in WalkDir::new(dir_path)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path().to_path_buf();
            if path == Path::new(LOG_PATH) {
                continue;
            }

            if entry.file_type().is_dir() {
                if !self.path_to_fd.contains_key(&path) {
                    let _ = self.watch_node(logger, &path, true, false);
                }
            } else if entry.file_type().is_file() {
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                let current_ino = meta.ino();

                match self.path_to_fd.get(&path).copied() {
                    None => {
                        // Brand-new file created at runtime: watch & evaluate its entropy
                        let _ = self.watch_node(logger, &path, false, true);
                    }
                    Some(existing_fd) => {
                        // Check if the file was atomically replaced by a new inode (`mv`)
                        let ino_changed = self
                            .fd_map
                            .get(&existing_fd)
                            .is_some_and(|n| n.ino != current_ino);
                        if ino_changed {
                            self.unwatch_fd(existing_fd);
                            let _ = self.watch_node(logger, &path, false, true);
                        }
                    }
                }
            }
        }
    }

    /// Opens a file or directory, registers it with `kqueue`, and optionally evaluates entropy.
    fn watch_node(
        &mut self,
        logger: &IronDomeLogger,
        path: &Path,
        is_dir: bool,
        evaluate_on_open: bool,
    ) -> Result<RawFd> {
        if self.fd_map.len() >= MAX_WATCHED_FDS {
            return Err(anyhow!("reached maximum kqueue watched descriptor limit"));
        }

        let meta = fs::symlink_metadata(path)?;
        let c_path = CString::new(path.as_os_str().as_bytes())?;

        // Open regular files with O_RDONLY so `pread` in `calculate_fd_entropy` succeeds.
        // Open directories with O_EVTONLY on macOS (or O_RDONLY on FreeBSD).
        #[cfg(target_os = "macos")]
        let open_flags = if is_dir {
            libc::O_EVTONLY | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC
        };
        #[cfg(target_os = "freebsd")]
        let open_flags = libc::O_RDONLY | libc::O_CLOEXEC;

        let fd = unsafe { libc::open(c_path.as_ptr(), open_flags) };
        if fd < 0 {
            let err = Error::last_os_error();
            return Err(anyhow!("failed to open {:?} for kqueue: {}", path, err));
        }

        let mut kev: libc::kevent = unsafe { std::mem::zeroed() };
        kev.ident = fd as libc::uintptr_t;
        kev.filter = libc::EVFILT_VNODE;
        kev.flags = (libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR) as _;
        kev.fflags = VNODE_FFLAGS;

        let ret = unsafe { libc::kevent(self.kq, &kev, 1, ptr::null_mut(), 0, ptr::null()) };
        if ret < 0 {
            let err = Error::last_os_error();
            unsafe { libc::close(fd) };
            logger.system_warn(&format!(
                "failed to register kevent for {:?}: {}",
                path, err
            ));
            return Err(anyhow!(err));
        }

        if let Some(old_fd) = self.path_to_fd.insert(path.to_path_buf(), fd) {
            self.fd_map.remove(&old_fd);
            unsafe { libc::close(old_fd) };
        }

        self.fd_map.insert(
            fd,
            WatchedNode {
                path: path.to_path_buf(),
                is_dir,
                ino: meta.ino(),
                last_atime: meta.atime(),
                last_atime_nsec: meta.atime_nsec(),
            },
        );

        if evaluate_on_open && !is_dir {
            self.evaluate_and_report_write(logger, path, fd);
        }

        Ok(fd)
    }

    fn unwatch_fd(&mut self, fd: RawFd) {
        if let Some(node) = self.fd_map.remove(&fd) {
            self.path_to_fd.remove(&node.path);
        }
        unsafe { libc::close(fd) };
    }

    fn evaluate_and_report_write(&mut self, logger: &IronDomeLogger, path: &Path, fd: RawFd) {
        let entropy_alert = match self.entropy_tracker.evaluate_fd(path, fd) {
            Ok(Some(alert)) => {
                let msg = match alert.old_entropy {
                    Some(old) => format!(
                        "File {:?} modified: entropy change from {:.2} to {:.2} (delta: {:.2} bits/byte)",
                        alert.path, old, alert.new_entropy, alert.delta
                    ),
                    None => format!(
                        "High entropy file {:?} written: {:.2} bits/byte",
                        alert.path, alert.new_entropy
                    ),
                };
                logger.alert("ENTROPY", &msg);
                Some(alert)
            }
            Ok(None) => None,
            Err(e) => {
                logger.system_warn(&format!("failed to compute entropy for {:?}: {}", path, e));
                None
            }
        };

        self.telemetry_tracker
            .on_file_write(logger, 0, path, entropy_alert.as_ref());
    }

    /// Inspects open file descriptors for advances in access time to detect read bursts.
    fn poll_atime_reads(&mut self, logger: &IronDomeLogger) {
        let mut accessed_paths = Vec::new();

        for (&fd, node) in &mut self.fd_map {
            if node.is_dir {
                continue;
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } == 0 {
                let atime = st.st_atime;
                let atime_nsec = st.st_atime_nsec;
                if atime > node.last_atime
                    || (atime == node.last_atime && atime_nsec > node.last_atime_nsec)
                {
                    node.last_atime = atime;
                    node.last_atime_nsec = atime_nsec;
                    accessed_paths.push(node.path.clone());
                }
            }
        }

        for path in accessed_paths {
            self.telemetry_tracker.on_file_access(logger, 0, &path);
        }
    }
}

impl Drop for BsdMonitor {
    fn drop(&mut self) {
        for &fd in self.fd_map.keys() {
            unsafe { libc::close(fd) };
        }
        unsafe { libc::close(self.kq) };
    }
}

/// Raises the soft open file descriptor limit (`RLIMIT_NOFILE`) on macOS/BSD
fn raise_fd_limit(logger: &IronDomeLogger) {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
        let target: libc::rlim_t = 8192;
        if rlim.rlim_cur < target {
            rlim.rlim_cur = if rlim.rlim_max < target {
                rlim.rlim_max
            } else {
                target
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
                logger.system_warn("could not raise RLIMIT_NOFILE for kqueue");
            }
        }
    }
}
