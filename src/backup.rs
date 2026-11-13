use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

use crate::entropy::{HIGH_ENTROPY_THRESHOLD, calculate_fd_entropy, is_sus_entropy_change};
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
    entropy: f64,
    last_snapshot_path: PathBuf,
}

#[derive(Debug)]
struct CandidateFile {
    src_path: PathBuf,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
    entropy: f64,
}

pub struct IncrementalBackupManager {
    backup_root: PathBuf,
    target_paths: Vec<PathBuf>,
    interval: Duration,
    manifest: HashMap<PathBuf, FileState>,
}

impl IncrementalBackupManager {
    pub fn new(
        backup_root: PathBuf,
        target_paths: Vec<PathBuf>,
        interval: Duration,
    ) -> Result<Self> {
        fs::create_dir_all(&backup_root)?;

        Ok(Self {
            backup_root,
            target_paths,
            interval,
            manifest: HashMap::with_capacity(1024),
        })
    }

    pub fn resolve_default_backup_dir() -> Result<PathBuf> {
        if let Ok(sudo_user) = std::env::var("SUDO_USER")
            && !sudo_user.is_empty()
            && sudo_user != "root"
            && let Some(home) = lookup_user_home(&sudo_user)
        {
            return Ok(home.join(BACKUP_DIR_NAME));
        }

        if let Ok(home) = std::env::var("HOME")
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

    /// Runs a single backup cycle.
    /// - Rejects modified files whose entropy jumped suspiciously (`is_sus_entropy_change`).
    /// - Rejects newly created post-baseline files with high entropy (`>= HIGH_ENTROPY_THRESHOLD`).
    /// - Preserves previously backed-up clean files even if they were deleted from the live disk.
    pub fn run_backup_cycle(
        &mut self,
        logger: &IronDomeLogger,
        is_initial_baseline: bool,
    ) -> Result<usize> {
        let live_files = self.scan_live_files();
        let mut to_copy: Vec<CandidateFile> = Vec::new();
        let mut unchanged_paths: Vec<PathBuf> = Vec::new();
        let mut rejected_ransomware = 0_usize;

        for (src_path, mtime, mtime_nsec, size) in live_files {
            match self.manifest.get(&src_path) {
                Some(prev) => {
                    let is_unchanged = prev.mtime == mtime
                        && prev.mtime_nsec == mtime_nsec
                        && prev.size == size
                        && prev.last_snapshot_path.exists();

                    if is_unchanged {
                        unchanged_paths.push(src_path);
                        continue;
                    }

                    // File was modified: check its new entropy BEFORE allowing it into backup
                    let Ok(file) = File::open(&src_path) else {
                        continue;
                    };
                    let Ok(new_entropy) = calculate_fd_entropy(file.as_raw_fd()) else {
                        continue;
                    };

                    if !is_initial_baseline && is_sus_entropy_change(prev.entropy, new_entropy) {
                        logger.system_warn(&format!(
                            "Backup blocked encrypted modification of {:?} (entropy {:.2} -> {:.2}); preserving clean copy",
                            src_path, prev.entropy, new_entropy
                        ));
                        rejected_ransomware += 1;
                        // Treat as unchanged so the clean previous version is carried forward!
                        unchanged_paths.push(src_path);
                    } else {
                        to_copy.push(CandidateFile {
                            src_path,
                            mtime,
                            mtime_nsec,
                            size,
                            entropy: new_entropy,
                        });
                    }
                }
                None => {
                    // Brand-new file not yet in manifest
                    let Ok(file) = File::open(&src_path) else {
                        continue;
                    };
                    let Ok(new_entropy) = calculate_fd_entropy(file.as_raw_fd()) else {
                        continue;
                    };

                    // If created after initial baseline with ciphertext-level entropy, reject it!
                    if !is_initial_baseline && new_entropy >= HIGH_ENTROPY_THRESHOLD {
                        logger.system_warn(&format!(
                            "Backup blocked newly created high-entropy file {:?} ({:.2} bits/byte)",
                            src_path, new_entropy
                        ));
                        rejected_ransomware += 1;
                        continue;
                    }

                    to_copy.push(CandidateFile {
                        src_path,
                        mtime,
                        mtime_nsec,
                        size,
                        entropy: new_entropy,
                    });
                }
            }
        }

        // If no legitimate new/modified files exist, do NOT rotate `latest` or create a new snapshot
        if !is_initial_baseline && to_copy.is_empty() {
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

        let mut handled_paths: HashSet<PathBuf> =
            HashSet::with_capacity(to_copy.len() + unchanged_paths.len());
        let mut copied_count = 0_usize;
        let mut linked_count = 0_usize;
        let mut preserved_deleted_count = 0_usize;

        // Copy legitimate new/modified files
        for item in to_copy {
            let dest_path = build_destination_path(&snapshot_dir, &item.src_path);
            if let Some(parent) = dest_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            if copy_file_stream(&item.src_path, &dest_path).is_ok() {
                if self.manifest.len() >= MAX_MANIFEST_ENTRIES
                    && !self.manifest.contains_key(&item.src_path)
                {
                    self.reclaim_memory();
                }

                handled_paths.insert(item.src_path.clone());
                self.manifest.insert(
                    item.src_path,
                    FileState {
                        mtime: item.mtime,
                        mtime_nsec: item.mtime_nsec,
                        size: item.size,
                        entropy: item.entropy,
                        last_snapshot_path: dest_path,
                    },
                );
                copied_count += 1;
            }
        }

        // Hard-link unchanged files (and files whose encrypted overwrite was blocked)
        for src_path in unchanged_paths {
            if let Some(prev) = self.manifest.get_mut(&src_path)
                && prev.last_snapshot_path.exists()
            {
                let dest_path = build_destination_path(&snapshot_dir, &src_path);
                if let Some(parent) = dest_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if fs::hard_link(&prev.last_snapshot_path, &dest_path).is_ok() {
                    prev.last_snapshot_path = dest_path;
                    linked_count += 1;
                    handled_paths.insert(src_path);
                }
            }
        }

        // Preserve previously backed-up clean files that were DELETED on the live disk
        // (defeats ransomware that writes `file.enc` and unlinks `file`)
        for (src_path, prev) in &mut self.manifest {
            if !handled_paths.contains(src_path) && prev.last_snapshot_path.exists() {
                let dest_path = build_destination_path(&snapshot_dir, src_path);
                if let Some(parent) = dest_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if fs::hard_link(&prev.last_snapshot_path, &dest_path).is_ok() {
                    prev.last_snapshot_path = dest_path;
                    preserved_deleted_count += 1;
                }
            }
        }

        // Atomically update `latest` symlink
        let latest_link = self.backup_root.join("latest");
        let _ = fs::remove_file(&latest_link);
        let _ = std::os::unix::fs::symlink(&snapshot_dir, &latest_link);

        logger.system_info(&format!(
            "Incremental backup {:?}: {} copied, {} hard-linked, {} deleted originals preserved, {} encrypted rejected",
            snap_name, copied_count, linked_count, preserved_deleted_count, rejected_ransomware
        ));

        Ok(copied_count)
    }

    fn scan_live_files(&self) -> Vec<(PathBuf, i64, i64, u64)> {
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
                .follow_links(false)
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
        self.manifest.clear();
        self.manifest.shrink_to(256);
    }
}

fn copy_file_stream(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut reader = File::open(src)?;
    let mut writer = File::create(dst)?;
    io::copy(&mut reader, &mut writer)
}

pub fn build_destination_path(snapshot_dir: &Path, src_path: &Path) -> PathBuf {
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
        return Some(PathBuf::from(dir_str));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_resists_both_in_place_and_unlink_ransomware() {
        let base_tmp =
            std::env::temp_dir().join(format!("irondome_ransom_bkp_{}", std::process::id()));
        let src_dir = base_tmp.join("watched");
        let bkp_dir = base_tmp.join("backups");
        let log_file = base_tmp.join("test.log");
        let _ = fs::remove_dir_all(&base_tmp);
        fs::create_dir_all(&src_dir).unwrap();

        let file_inplace = src_dir.join("notes.txt");
        let file_unlinked = src_dir.join("credentials.conf");
        let file_normal = src_dir.join("todo.md");

        let clean_notes = "Important project architecture notes.\n".repeat(100);
        let clean_creds = "DB_HOST=localhost\nDB_USER=admin\n".repeat(100);
        let clean_todo = "1. Finish Iron Dome\n".repeat(100);

        fs::write(&file_inplace, &clean_notes).unwrap();
        fs::write(&file_unlinked, &clean_creds).unwrap();
        fs::write(&file_normal, &clean_todo).unwrap();

        let logger = IronDomeLogger::init_with_path(&log_file).unwrap();
        let mut mgr = IncrementalBackupManager::new(
            bkp_dir.clone(),
            vec![src_dir.clone()],
            Duration::from_secs(5),
        )
        .unwrap();

        // 1. Initial baseline snapshot backs up all 3 clean files
        assert_eq!(mgr.run_backup_cycle(&logger, true).unwrap(), 3);

        // 2. Simulate Ransomware Attack:
        //    a) Overwrite `notes.txt` in-place with uniform high-entropy ciphertext (8.0 bits/byte)
        //    b) Write `credentials.conf.enc` with ciphertext and DELETE original `credentials.conf`
        //    c) Also make a legitimate plaintext edit to `todo.md` to force a new snapshot
        thread::sleep(Duration::from_millis(20));
        let ciphertext: Vec<u8> = (0..16384).map(|i| ((i * 73 + 19) & 0xFF) as u8).collect();
        fs::write(&file_inplace, &ciphertext).unwrap();

        let encrypted_new_file = src_dir.join("credentials.conf.enc");
        fs::write(&encrypted_new_file, &ciphertext).unwrap();
        fs::remove_file(&file_unlinked).unwrap();

        let updated_todo = format!("{clean_todo}2. Test ransomware recovery\n");
        fs::write(&file_normal, &updated_todo).unwrap();

        // 3. Run incremental backup cycle after the ransomware attack
        let copied = mgr.run_backup_cycle(&logger, false).unwrap();
        // Only the 1 legitimate plaintext edit (`todo.md`) should be copied!
        assert_eq!(copied, 1);

        let latest_dir = bkp_dir.join("latest");

        // Verify `notes.txt` in `latest` still has the CLEAN original plaintext (not ciphertext)
        let backed_up_notes = build_destination_path(&latest_dir, &file_inplace);
        assert_eq!(fs::read_to_string(backed_up_notes).unwrap(), clean_notes);

        // Verify deleted `credentials.conf` is STILL preserved in `latest`
        let backed_up_creds = build_destination_path(&latest_dir, &file_unlinked);
        assert_eq!(fs::read_to_string(backed_up_creds).unwrap(), clean_creds);

        // Verify `credentials.conf.enc` was NEVER allowed into `latest`
        let backed_up_enc = build_destination_path(&latest_dir, &encrypted_new_file);
        assert!(!backed_up_enc.exists());

        // Verify legitimate edit to `todo.md` WAS updated in `latest`
        let backed_up_todo = build_destination_path(&latest_dir, &file_normal);
        assert_eq!(fs::read_to_string(backed_up_todo).unwrap(), updated_todo);

        let _ = fs::remove_dir_all(&base_tmp);
    }
}
