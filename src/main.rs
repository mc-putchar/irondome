mod monitor;
mod entropy;
mod logger;
mod daemon;

use monitor::linux::LinuxMonitor;
use logger::{IronDomeLogger, LogLevel};

use std::{env, path::Path};


unsafe extern "C" { fn getuid() -> u32; }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1);
    if path.is_none() {
        return Err("Provide a path to watch".into());
    }
    let path = path.unwrap();
    let path = Path::new(&path);
    if !path.is_dir() {
        return Err("Path must be an existing directory".into());
    }

    let absolute_path = path.canonicalize()?;
    println!("Watching: {}", absolute_path.display());

    let logger = match IronDomeLogger::init() {
        Ok(log) => log,
        Err(e) => {
            eprintln!("Critical Failure: Could not initialize log file: {}", e);
            std::process::exit(1);
        }
    };

    println!("Starting irondome daemon");
    // daemon::daemonize();

    let _ = logger.log(LogLevel::Info, "SYSTEM", "Iron Dome daemon started successfully.");


    // let mut monitor = LinuxMonitor::init_watcher(path);
    // monitor.init_watcher(&absolute_path.to_string_lossy())?;
    loop {
        // Mock event trigger
        let suspicious_activity_detected = true;
        let file_path = "/critical/path/compromised.txt";

        if suspicious_activity_detected {
            if let Err(_err) = logger.log(
                LogLevel::Alert,
                "ENTROPY",
                &format!("Suspicious entropy jump detected on file: {}", file_path)
            ) {
                // TODO: Fail-safe: could attempt an alternate fallback write to /tmp or /dev/kmsg here
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Ok(())
}
