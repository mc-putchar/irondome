use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

const LOG_DIR: &str = "/var/log/irondome";
pub const LOG_PATH: &str = "/var/log/irondome/irondome.log";

pub enum LogLevel {
    Info,
    Warning,
    Error,
    Event,
    Alert,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Event => "EVENT",
            LogLevel::Alert => "ALERT",
        }
    }
}

pub struct IronDomeLogger {
    // Wrapped in a Mutex to ensure thread-safety without external crates
    file: Mutex<std::fs::File>,
}

impl IronDomeLogger {
    /// Initializes the logger, creating directories and the log file if missing.
    pub fn init() -> Result<Self> {
        if !Path::new(LOG_DIR).exists() {
            create_dir_all(LOG_DIR)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_PATH)?;

        Ok(IronDomeLogger {
            file: Mutex::new(file),
        })
    }

    /// Helper to fetch a simple ISO-like timestamp without external time crates
    fn get_timestamp(&self) -> String {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = since_the_epoch.as_secs();

        format!("{}", secs)
    }

    /// Writes a structured message to the log file.
    /// It returns a Result to allow the main loop to handle failures gracefully.
    pub fn log(&self, level: LogLevel, component: &str, message: &str) -> Result<()> {
        let timestamp = self.get_timestamp();
        let log_line = format!(
            "[{}] [{}] [{}] {}\n",
            timestamp,
            level.as_str(),
            component,
            message
        );

        // Lock the file mutex to prevent log scrambling across threads/tasks
        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("Failed to acquire log lock"))?;

        file_guard.write_all(log_line.as_bytes())?;
        file_guard.flush()?;

        Ok(())
    }

    pub fn system_info(&self, message: &str) {
        let _ = self.log(LogLevel::Info, "SYSTEM", message);
    }

    pub fn system_warn(&self, message: &str) {
        let _ = self.log(LogLevel::Warning, "SYSTEM", message);
    }

    pub fn system_error(&self, message: &str) {
        let _ = self.log(LogLevel::Error, "SYSTEM", message);
    }

    pub fn event(&self, pid: i32, path: PathBuf, mask: u64) {
        let _ = self.log(
            LogLevel::Event,
            "MONITOR",
            format!("PID {} touched {:?} (mask: {:#?})", pid, path, mask).as_str(),
        );
    }
}
