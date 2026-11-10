use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

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
