use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum LogLevel {
    Info,
    Warning,
    Alert,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
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
    pub fn init() -> Result<Self, std::io::Error> {
        let log_dir = "/var/log/irondome";
        let log_path = format!("{}/irondome.log", log_dir);

        if !Path::new(log_dir).exists() {
            create_dir_all(log_dir)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

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
    pub fn log(&self, level: LogLevel, component: &str, message: &str) -> Result<(), std::io::Error> {
        let timestamp = self.get_timestamp();
        let log_line = format!(
            "[{}] [{}] [{}] {}\n",
            timestamp,
            level.as_str(),
            component,
            message
        );

        // Lock the file mutex to prevent log scrambling across threads/tasks
        let mut file_guard = self.file.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "Failed to acquire log lock")
        })?;

        file_guard.write_all(log_line.as_bytes())?;
        file_guard.flush()?;

        Ok(())
    }
}
