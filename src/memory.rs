use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
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

pub fn is_memory_pressure() -> bool {
    heap_usage_bytes() >= SOFT_HEAP_LIMIT_BYTES || rss_usage_bytes() >= SOFT_RSS_LIMIT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_allocator_counts_alloc_and_dealloc() {
        let before = heap_usage_bytes();
        let buf: Vec<u8> = vec![42_u8; 2 * 1024 * 1024];
        let during = heap_usage_bytes();

        assert!(
            during >= before + (2 * 1024 * 1024),
            "expected heap_usage_bytes to increase by 2MB"
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
