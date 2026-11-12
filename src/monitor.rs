use crate::logger::IronDomeLogger;

use std::path::PathBuf;

#[allow(unused_imports)]
use anyhow::{Result, anyhow};

pub trait PlatformMonitor {
    fn init(logger: &IronDomeLogger, target_paths: &[PathBuf]) -> Result<Self>
    where
        Self: Sized;

    fn poll_events(&mut self, logger: &IronDomeLogger) -> Result<()>;
}

pub struct FileEvent {
    pub path: String,
    pub mask: u32,
}

// Conditionally compile modules based on the Target OS
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod bsd;
#[cfg(target_os = "linux")]
pub mod linux;

pub fn init_monitor(
    logger: &IronDomeLogger,
    target_paths: &[PathBuf],
) -> Result<Box<dyn PlatformMonitor>> {
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    return Err(anyhow!("Unsupported OS for file monitoring"));

    #[cfg(target_os = "linux")]
    return Ok(Box::new(linux::LinuxMonitor::init(logger, target_paths)?));

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    return Ok(Box::new(bsd::BsdMonitor::init(logger, target_paths)?));
}
