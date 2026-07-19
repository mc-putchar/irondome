pub trait PlatformMonitor {
    fn init_watcher(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn poll_events(&mut self) -> Vec<FileEvent>;
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
