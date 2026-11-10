use crate::logger::IronDomeLogger;

use super::PlatformMonitor;

use std::ffi::CString;
use std::fs;
use std::io::{self, Error};
use std::os::fd::RawFd;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

#[repr(align(8))]
struct AlignedBuf([u8; 4096]);

pub struct LinuxMonitor {
    fd: i32,
}

impl PlatformMonitor for LinuxMonitor {
    fn init(logger: &IronDomeLogger, target_paths: &Vec<PathBuf>) -> Result<Self> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            logger.system_error("failed to initialize filesystem watch");
            return Err(anyhow!(Error::last_os_error()));
        }

        for target_path in target_paths {
            let flags = libc::FAN_MARK_ADD;
            let mut mask: u64 = libc::FAN_ACCESS | libc::FAN_CLOSE_WRITE | libc::FAN_MODIFY;
            if target_path.is_dir() {
                mask |= libc::FAN_EVENT_ON_CHILD;
                for entry in WalkDir::new(target_path) {
                    let entry = &entry.unwrap().into_path();
                    watch_path(logger, fd, entry, flags, mask)?;
                }
                // TODO: if a new subdirectory is created inside one of these after init,
                // catch the event and also mark that subdirectory
            } else {
                watch_path(logger, fd, target_path, flags, mask)?
            }
        }

        Ok(LinuxMonitor { fd })
    }

    fn poll_events(&mut self, logger: &IronDomeLogger) -> Result<()> {
        let mut buf = AlignedBuf([0_u8; 4096]);
        let meta_size = size_of::<libc::fanotify_event_metadata>();

        let len = unsafe {
            libc::read(
                self.fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len < 0 {
            let err = Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            logger.system_error(format!("failed to read fanotify fd: {}", err).as_str());
            return Err(anyhow!("failed to read fanotify fd: {}", err));
        }

        let mut offset = 0_usize;
        let total = len as usize;

        while offset + meta_size <= total {
            let meta =
                unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION as u8 {
                panic!("Mismatched fanotify metadata version");
            }
            if meta.event_len as usize == 0_usize {
                break;
            }

            if (meta.mask & libc::FAN_Q_OVERFLOW) != 0 {
                logger.system_warn("fanotify queue overflowed!");
            }

            if meta.fd >= 0 {
                handle_event(logger, meta.fd, meta.pid, meta.mask);

                unsafe { libc::close(meta.fd) };
            }

            offset += meta.event_len as usize;
        }

        Ok(())
    }
}

impl Drop for LinuxMonitor {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn watch_path(
    logger: &IronDomeLogger,
    fd: i32,
    target_path: &PathBuf,
    flags: u32,
    mask: u64,
) -> Result<()> {
    let c_path = CString::new(target_path.to_str().unwrap())?;

    let ret = unsafe { libc::fanotify_mark(fd, flags, mask, libc::AT_FDCWD, c_path.as_ptr()) };
    if ret == -1 {
        unsafe { libc::close(fd) };
        let err = Error::last_os_error();
        logger.system_error(
            format!(
                "failed to add watch on the path specified: {}",
                err.to_string()
            )
            .as_str(),
        );
        Err(anyhow!(err))
    } else {
        Ok(())
    }
}

fn handle_event(logger: &IronDomeLogger, fd: RawFd, pid: i32, mask: u64) {
    if pid as u32 == std::process::id() {
        return;
    }

    let proc_fd_path = format!("/proc/self/fd/{}", fd);
    if let Ok(real_path) = fs::read_link(&proc_fd_path) {
        logger.event(pid, real_path, mask);
    }
}
