use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, thread};

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

use crate::logger::{IronDomeLogger, LOG_PATH, format_utc_iso8601};
use crate::memory::is_memory_pressure;

const MAX_MANIFEST_ENTRIES: usize = 50_000;
const MAX_SINGLE_FILE_BACKUP_BYTES: u64 = 50 * 1024 * 1024;

const BACKUP_DIR_NAME: &str = "backup";

#[derive(Debug, Clone)]
struct FileState {
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
    last_snapshot_path: PathBuf,
}

pub struct IncrementalBackupManager {
    backup_root: PathBuf,
    target_paths: Vec<PathBuf>,
    interval: Duration,
    manifest: HashMap<PathBuf, FileState>,
    quarantined: Arc<Mutex<HashSet<PathBuf>>>,
}

impl IncrementalBackupManager {
    pub fn new(
        backup_root: PathBuf,
        target_paths: Vec<PathBuf>,
        interval: Duration,
        quarantined: Arc<Mutex<HashSet<PathBuf>>>,
    ) -> Result<Self> {
        std::fs::create_dir_all(&backup_root)?;

        Ok(Self {
            backup_root,
            target_paths,
            interval,
            manifest: HashMap::with_capacity(1024),
            quarantined,
        })
    }

    pub fn resolve_default_backup_dir() -> Result<PathBuf> {
        if let Ok(sudo_user) = env::var("SUDO_USER")
            && !sudo_user.is_empty()
            && sudo_user != "root"
            && let Some(home) = lookup_user_home(&sudo_user)
        {
            return Ok(home.join(BACKUP_DIR_NAME));
        }

        if let Ok(home) = env::var("HOME")
            && !home.is_empty()
        {
            return Ok(PathBuf::from(home).join(BACKUP_DIR_NAME));
        }

        if let Some(root_home) = lookup_user_home("root") {
            return Ok(root_home.join(BACKUP_DIR_NAME));
        }

        Err(anyhow!("Could not resolve user HOME directory for backups"))
    }

    pub fn spawn(mut self, logger: Arc<IronDomeLogger>) -> Result<thread::JoinHandle<()>> {
        let handle = thread::Builder::new()
            .name("irondome-backup".to_string())
            .stack_size(512 * 1024)
            .spawn(move || {
                logger.system_info(&format!(
                    "Backup engine initialized at {:?} (interval: {}s)",
                    self.backup_root,
                    self.interval.as_secs()
                ));

                if let Err(e) = self.run_backup_cycle(&logger, true) {
                    logger.system_error(&format!("Initial backup failed: {e}"));
                }

                loop {
                    thread::sleep(self.interval);

                    if is_memory_pressure() {
                        logger.system_warn("Memory pressure high; reclaiming backup manifest");
                        self.reclaim_memory();
                    }

                    if let Err(e) = self.run_backup_cycle(&logger, false) {
                        logger.system_error(&format!("Incremental backup cycle error: {e}"));
                    }
                }
            })?;

        Ok(handle)
    }

    pub fn run_backup_cycle(
        &mut self,
        logger: &IronDomeLogger,
        force_snapshot: bool,
    ) -> Result<usize> {
        let candidates = self.collect_candidate_files();
        let quarantined_guard = self
            .quarantined
            .lock()
            .map_err(|_| anyhow!("Failed to lock quarantine set"))?
            .clone();

        let has_changes = force_snapshot
            || candidates.iter().any(|(src, mtime, mtime_nsec, size)| {
                if quarantined_guard.contains(src) {
                    return false;
                }
                match self.manifest.get(src) {
                    Some(prev) => {
                        prev.mtime != *mtime || prev.mtime_nsec != *mtime_nsec || prev.size != *size
                    }
                    None => true,
                }
            });

        if !has_changes {
            return Ok(0);
        }

        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let snap_name = format!(
            "snapshot_{}",
            format_utc_iso8601(since_epoch).replace([':', '.'], "-")
        );
        let snapshot_dir = self.backup_root.join(&snap_name);
        fs::create_dir_all(&snapshot_dir)?;

        let mut copied_count = 0_usize;
        let mut linked_count = 0_usize;
        let mut skipped_quarantined = 0_usize;

        for (src_path, mtime, mtime_nsec, size) in candidates {
            let dest_path = build_dest_path(&snapshot_dir, &src_path);
            if let Some(parent) = dest_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            // Skip files that are quarantined for suspicious entropy
            if quarantined_guard.contains(&src_path) {
                skipped_quarantined += 1;
                match self.manifest.get(&src_path) {
                    Some(prev) => {
                        let _ = fs::hard_link(&prev.last_snapshot_path, &dest_path);
                    }
                    _ => {
                        // TODO: handle a quarantined file that has not been backed up yet
                    }
                }
                continue;
            }

            let unchanged = match self.manifest.get(&src_path) {
                Some(prev) => {
                    prev.mtime == mtime
                        && prev.mtime_nsec == mtime_nsec
                        && prev.size == size
                        && prev.last_snapshot_path.exists()
                }
                None => false,
            };

            if unchanged
                && let Some(prev) = self.manifest.get_mut(&src_path)
                && fs::hard_link(&prev.last_snapshot_path, &dest_path).is_ok()
            {
                prev.last_snapshot_path = dest_path;
                linked_count += 1;
                continue;
            }

            match copy_file_stream(&src_path, &dest_path) {
                Ok(_) => {
                    if self.manifest.len() >= MAX_MANIFEST_ENTRIES
                        && !self.manifest.contains_key(&src_path)
                    {
                        self.reclaim_memory();
                    }

                    self.manifest.insert(
                        src_path,
                        FileState {
                            mtime,
                            mtime_nsec,
                            size,
                            last_snapshot_path: dest_path,
                        },
                    );
                    copied_count += 1;
                }
                Err(e) => {
                    logger.system_warn(&format!("Failed to copy file {:?}: {}", src_path, e));
                }
            }
        }

        let latest_link = self.backup_root.join("latest");
        let _ = fs::remove_file(&latest_link);
        let _ = std::os::unix::fs::symlink(&snapshot_dir, &latest_link);

        logger.system_info(&format!(
            "Incremental backup {:?}: {} copied, {} hard linked, {} quarantined skipped",
            snap_name, copied_count, linked_count, skipped_quarantined
        ));

        Ok(copied_count)
    }

    fn collect_candidate_files(&self) -> Vec<(PathBuf, i64, i64, u64)> {
        let mut files = Vec::new();
        let log_path = Path::new(LOG_PATH);

        for target in &self.target_paths {
            if target.starts_with(&self.backup_root) {
                continue;
            }

            if target.is_file() {
                if let Ok(meta) = fs::symlink_metadata(target)
                    && meta.is_file()
                    && meta.len() <= MAX_SINGLE_FILE_BACKUP_BYTES
                {
                    files.push((target.clone(), meta.mtime(), meta.mtime_nsec(), meta.len()));
                }
                continue;
            }

            for entry in WalkDir::new(target)
                .into_iter()
                .filter_entry(|e| !e.path().starts_with(&self.backup_root))
                .flatten()
            {
                let path = entry.path();
                if path == log_path || !entry.file_type().is_file() {
                    continue;
                }
                if let Ok(meta) = entry.metadata()
                    && meta.len() <= MAX_SINGLE_FILE_BACKUP_BYTES
                {
                    files.push((
                        path.to_path_buf(),
                        meta.mtime(),
                        meta.mtime_nsec(),
                        meta.len(),
                    ));
                }
            }
        }

        files
    }

    pub fn reclaim_memory(&mut self) {
        // self.manifest.clear();
        // self.manifest.shrink_to(256);
    }
}

fn copy_file_stream(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut reader = File::open(src)?;
    let mut writer = File::create(dst)?;
    io::copy(&mut reader, &mut writer)
}

fn build_dest_path(snapshot_dir: &Path, src_path: &Path) -> PathBuf {
    let mut dest = snapshot_dir.to_path_buf();
    for comp in src_path.components() {
        if let Component::Normal(part) = comp {
            dest.push(part);
        }
    }

    dest
}

fn lookup_user_home(username: &str) -> Option<PathBuf> {
    let c_user = CString::new(username).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = [0_i8; 1024];

    let ret = unsafe {
        libc::getpwnam_r(
            c_user.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };

    if ret == 0 && !result.is_null() && !pwd.pw_dir.is_null() {
        let dir_str = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_str().ok()?;

        Some(PathBuf::from(dir_str))
    } else {
        None
    }
}
