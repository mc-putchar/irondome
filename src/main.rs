use irondome::daemon::{daemonize, is_root};
use irondome::logger::{IronDomeLogger, LOG_PATH};
use irondome::monitor::PlatformMonitor;
use irondome::monitor::linux::LinuxMonitor;

use anyhow::{Context, Result, anyhow};
use std::{
    env,
    path::{Path, PathBuf},
};

fn main() -> Result<()> {
    if !is_root() {
        return Err(anyhow!("Not running as root. Iron Dome must run as root."));
    }

    let logger = IronDomeLogger::init()
        .with_context(|| format!("failed to create log file at '{}'", LOG_PATH))?;

    let args: Vec<String> = env::args().collect();
    let target_paths: Vec<PathBuf> = get_target_paths(&args[1..])?;
    if target_paths.is_empty() {
        return Err(anyhow!("No valid path specified."));
    }

    logger.system_info("Starting irondome daemon...");
    let _pid_file = daemonize()?;

    #[cfg(target_os = "linux")]
    let mut monitor = LinuxMonitor::init(&logger, &target_paths)?;
    #[cfg(not(target_os = "linux"))]
    return Err(anyhow!("OS not supported!"));

    loop {
        monitor.poll_events(&logger)?
    }
}

fn get_target_paths(args: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for arg in args {
        let path = Path::new(arg)
            .canonicalize()
            .with_context(|| format!("Path '{}' is not accessible", arg))?;
        println!("Monitoring: {:#?}", path);
        paths.push(path);
    }

    Ok(paths)
}
