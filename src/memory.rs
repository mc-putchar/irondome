use std::alloc::{GlobalAlloc, Layout, System};
#[allow(unused_imports)]
use std::fs::File;
#[allow(unused_imports)]
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const HARD_MEM_LIMIT_BYTES: usize = 100 * 1024 * 1024;
pub const SOFT_HEAP_LIMIT_BYTES: usize = 65 * 1024 * 1024;
pub const SOFT_RSS_LIMIT_BYTES: usize = 80 * 1024 * 1024;

pub struct TrackedAllocator;

static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }

        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        ALLOCATED_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                ALLOCATED_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            } else {
                ALLOCATED_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }

        new_ptr
    }
}

#[global_allocator]
static GLOBAL: TrackedAllocator = TrackedAllocator;

/// Check current heap usage
pub fn heap_usage_bytes() -> usize {
    ALLOCATED_BYTES.load(Ordering::Relaxed)
}

/// Check total process Resident Set Size (RSS) via procfs
pub fn rss_usage_bytes() -> usize {
    #[cfg(target_os = "linux")]
    {
        let mut buf = [0_u8; 64];

        if let Ok(mut file) = File::open("/proc/self/statm")
            && let Ok(n) = file.read(&mut buf)
            && let Ok(s) = std::str::from_utf8(&buf[..n])
            && let Some(rss_pages_str) = s.split_whitespace().nth(1)
            && let Ok(pages) = rss_pages_str.parse::<usize>()
        {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
            return pages * page_size;
        }
        0
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 {
            #[cfg(target_os = "macos")]
            return usage.ru_maxrss as usize; // macOS reports ru_maxrss in bytes
            #[cfg(target_os = "freebsd")]
            return (usage.ru_maxrss as usize) * 1024; // FreeBSD reports ru_maxrss in KB
        }
        0
    }
}

pub fn is_memory_pressure() -> bool {
    heap_usage_bytes() >= SOFT_HEAP_LIMIT_BYTES || rss_usage_bytes() >= SOFT_RSS_LIMIT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_allocator_counts_alloc_and_dealloc() {
        let alloc_size = 4 * 1024 * 1024;
        let epsilon_tolerance = 128 * 1024;

        let before = heap_usage_bytes();
        let buf: Vec<u8> = vec![42_u8; alloc_size];
        let during = heap_usage_bytes();

        assert!(
            during + epsilon_tolerance >= before + alloc_size,
            "expected heap_usage_bytes to increase at least by {alloc_size} bytes (before={before}, during={during})"
        );
        std::hint::black_box(&buf);
        drop(buf);

        let after = heap_usage_bytes();
        assert!(
            after < during,
            "expected heap_usage_bytes to drop after deallocation"
        );
    }
}
