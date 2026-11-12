use std::env;
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
    if !is_root() {
        return Err(anyhow!("Iron Dome must be run as root."));
    }

    let mut pid_file = acquire_pid_lock(PID_FILE_PATH)?;

    env::set_current_dir("/")?;

    unsafe {
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

        // Redirect standard fds to /dev/null
        let null_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null_fd >= 0 {
            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::dup2(null_fd, libc::STDOUT_FILENO);
            libc::dup2(null_fd, libc::STDERR_FILENO);
            if null_fd > 2 {
                libc::close(null_fd);
            }
        }
    }

    pid_file.set_len(0)?;
    writeln!(pid_file, "{}", std::process::id())?;
    pid_file.sync_all()?;

    Ok(pid_file)
}

fn acquire_pid_lock(pid_path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o640)
        .open(pid_path)?;

    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret < 0 {
        return Err(anyhow!("Another instance of irondome is already running"));
    }

    Ok(file)
}
