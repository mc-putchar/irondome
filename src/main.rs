use irondome::daemon::{daemonize, is_root};
use irondome::logger::{IronDomeLogger, LOG_PATH};
use irondome::monitor::PlatformMonitor;
use irondome::monitor::linux::LinuxMonitor;
use irondome::signals::setup_signal_handlers;

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

const DEFAULT_TARGET_PATHS: &[&str] = &["/etc", "/home", "/var/www"];

fn main() -> Result<()> {
    if !is_root() {
        return Err(anyhow!("Not running as root. Iron Dome must run as root."));
    }

    let logger = IronDomeLogger::init()
        .with_context(|| format!("failed to create log file at '{}'", LOG_PATH))?;

    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let target_paths: Vec<PathBuf> = get_target_paths(&args)?;
    if target_paths.is_empty() {
        return Err(anyhow!("No valid path specified."));
    }

    logger.system_info("Starting irondome daemon...");
    let _pid_file = daemonize()?;
    setup_signal_handlers()?;

    #[cfg(target_os = "linux")]
    let mut monitor = LinuxMonitor::init(&logger, &target_paths)?;
    #[cfg(not(target_os = "linux"))]
    return Err(anyhow!("OS not supported!"));

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
