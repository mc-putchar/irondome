use irondome::backup::IncrementalBackupManager;
use irondome::daemon::{daemonize, is_root};
use irondome::logger::{IronDomeLogger, LOG_PATH};
use irondome::monitor::init_monitor;
use irondome::signals::setup_signal_handlers;

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

const NO_ARGS_MESSAGE: &str = "No arguments provided.
Watching default paths: /etc, /home.";
const DEFAULT_TARGET_PATHS: &[&str] = &["/etc", "/home"];
const DEFAULT_BACKUP_INTERVAL_SECS: u64 = 5;

fn main() -> Result<()> {
    if !is_root() {
        return Err(anyhow!("Not running as root. Iron Dome must run as root."));
    }

    let logger = Arc::new(
        IronDomeLogger::init()
            .with_context(|| format!("failed to create log file at '{}'", LOG_PATH))?,
    );

    let args: Vec<String> = env::args().skip(1).collect();
    let path_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if path_args.is_empty() {
        println!("{}", NO_ARGS_MESSAGE);
    }

    let target_paths: Vec<PathBuf> = get_target_paths(&path_args)?;
    if target_paths.is_empty() {
        return Err(anyhow!("No valid path specified."));
    }

    let backup_interval_secs = DEFAULT_BACKUP_INTERVAL_SECS;
    let backup_root = IncrementalBackupManager::resolve_default_backup_dir()?;
    let quarantined = Arc::new(Mutex::new(HashSet::new()));
    let backup_running = Arc::new(AtomicBool::new(false));

    logger.system_info("Starting irondome daemon...");

    // Keep ref to pid file to keep the lock on it
    let _pid_file = daemonize()?;
    setup_signal_handlers()?;

    let mut monitor = init_monitor(
        &logger,
        &target_paths,
        backup_root.clone(),
        Arc::clone(&quarantined),
        Arc::clone(&backup_running),
    )?;

    let backup_manager = IncrementalBackupManager::new(
        backup_root,
        target_paths.clone(),
        Duration::from_secs(backup_interval_secs),
        quarantined,
        backup_running,
    )?;
    let _backup_handle = backup_manager.spawn(Arc::clone(&logger))?;

    loop {
        if let Err(e) = monitor.poll_events(&logger) {
            logger.system_error(&format!("Monitor poll error: {e}"));
        }
    }
}

fn get_target_paths(args: &[&str]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for arg in if args.is_empty() {
        DEFAULT_TARGET_PATHS
    } else {
        args
    } {
        let path = Path::new(arg)
            .canonicalize()
            .with_context(|| format!("Path '{}' is not accessible", arg))?;
        println!("Watching path: {:?}", path);
        paths.push(path);
    }

    Ok(paths)
}
