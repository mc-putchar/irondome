use super::{PlatformMonitor, FileEvent};

use std::ffi::CString;
use std::os::raw::{c_int, c_char, c_void};

pub struct LinuxMonitor {
    fd: i32,
}

impl PlatformMonitor for LinuxMonitor {
    fn init_watcher(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.fd = init_watch()?;
        add_path(self.fd, path)?;

        Ok(())
    }

    fn poll_events(&mut self) -> Vec<FileEvent> {
        // Call read() on self.fd and parse inotify_event structs
        Vec::new()
    }
}

impl Drop for LinuxMonitor {
    fn drop(&mut self) {
        close_watch(self.fd).ok();
    }
}

unsafe extern "C" {
    fn inotify_init1(flags: c_int) -> c_int;
    fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}

const IN_NONBLOCK: c_int = 0x00000800;
const IN_MODIFY: u32 = 0x00000002;
const IN_DELETE: u32 = 0x00000200;

fn init_watch() -> Result<i32, Box<dyn std::error::Error>> {
        let fd: i32 = unsafe { inotify_init1(IN_NONBLOCK) } as i32;
        if fd == -1 {
            return Err("Failed to setup watch on the path specified".into());
        }

        Ok(fd)
}

fn add_path(fd: i32, target_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let c_path = CString::new(target_dir)?;
    let err = unsafe { inotify_add_watch(fd, c_path.as_ptr(), IN_MODIFY | IN_DELETE) };
    if err == -1 {
        return Err("Failed to add watch on the path specified".into());
    }

    Ok(())
}

fn close_watch(fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    unsafe { close(fd) };

    Ok(())
}
