use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Result, anyhow};

const PID_FILE_PATH: &str = "/run/irondome.pid";

pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub fn daemonize() -> Result<File> {
    let pid_file = acquire_pid_lock(PID_FILE_PATH)?;

    unsafe {
        if libc::getuid() != 0 {
            eprintln!("Error: Iron Dome must be run as root.");
            std::process::exit(1);
        }

        // First fork
        let pid = libc::fork();
        if pid < 0 {
            std::process::exit(1);
        }
        // Exit parent
        if pid > 0 {
            std::process::exit(0);
        }

        // Create a new SID for the child process
        if libc::setsid() < 0 {
            std::process::exit(1);
        }

        // Second fork (prevents acquiring a controlling terminal)
        let pid = libc::fork();
        if pid < 0 {
            std::process::exit(1);
        }
        if pid > 0 {
            std::process::exit(0);
        }

        // Set file permissions
        libc::umask(0o027);

        // Close standard descriptors to complete detach
        libc::close(0);
        libc::close(1);
        libc::close(2);
    }

    Ok(pid_file)
}

fn acquire_pid_lock(pid_path: &str) -> Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o640)
        .open(pid_path)?;

    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret < 0 {
        return Err(anyhow!("Another instance of irondome is already running"));
    }

    file.set_len(0)?;
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;

    Ok(file)
}
