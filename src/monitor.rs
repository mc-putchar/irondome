use std::path::PathBuf;

use anyhow::Result;

use crate::logger::IronDomeLogger;

pub trait PlatformMonitor {
    fn init(logger: &IronDomeLogger, target_paths: &Vec<PathBuf>) -> Result<Self>
    where
        Self: Sized;

    fn poll_events(&mut self, logger: &IronDomeLogger) -> Result<()>;
}

pub struct FileEvent {
    pub path: String,
    pub mask: u32,
}

// Conditionally compile modules based on the Target OS
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod bsd;
