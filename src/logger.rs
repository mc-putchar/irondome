use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;

pub const LOG_PATH: &str = "/var/log/irondome/irondome.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Initializes the logger at the default path (`/var/log/irondome/irondome.log`)
    pub fn init() -> Result<Self> {
        Self::init_with_path(Path::new(LOG_PATH))
    }

    /// Initializes the logger, creating directories and the log file if missing.
    pub fn init_with_path(log_path: &Path) -> Result<Self> {
        if let Some(parent) = log_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        Ok(IronDomeLogger {
            file: Mutex::new(file),
        })
    }

    pub fn format_entry(d: Duration, level: LogLevel, component: &str, message: &str) -> String {
        let timestamp = format_utc_iso8601(d);
        format!(
            "{} [{:<5}] [{}] {}\n",
            timestamp,
            level.as_str(),
            component,
            message
        )
    }

    /// Writes a structured message to the log file.
    /// It returns a Result to allow the main loop to handle failures gracefully.
    pub fn log(&self, level: LogLevel, component: &str, message: &str) -> Result<()> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let log_line = Self::format_entry(since_epoch, level, component, message);

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

    pub fn alert(&self, category: &str, message: &str) {
        let _ = self.log(LogLevel::Alert, category, message);
    }
}

/// Converts duration to ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SS.mmmZ`)
pub fn format_utc_iso8601(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs() as libc::time_t;
    let millis = since_epoch.subsec_millis();

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::gmtime_r(&secs, &mut tm);
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_epoch_zero() {
        let ts = format_utc_iso8601(Duration::from_secs(0));
        assert_eq!(ts, "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn test_logger_writes_standardized_lines() {
        let tmp_path =
            std::env::temp_dir().join(format!("irondome_log_test_{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);

        let logger = IronDomeLogger::init_with_path(&tmp_path).expect("failed to init logger");
        logger.system_info("test initialized");
        logger.alert("ENTROPY", "file /tmp/a.out randomized to 7.95");

        let content = std::fs::read_to_string(&tmp_path).expect("failed to read test log");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("[INFO ] [SYSTEM] test initialized"));
        assert!(lines[1].contains("[ALERT] [ENTROPY] file /tmp/a.out randomized to 7.95"));

        let _ = std::fs::remove_file(&tmp_path);
    }
}
