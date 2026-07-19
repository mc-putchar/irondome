unsafe extern "C" {
    fn fork() -> i32;
    fn setsid() -> i32;
    fn umask(mask: u32) -> u32;
    fn close(fd: i32) -> i32;
    fn getuid() -> u32;
}

pub fn daemonize() {
    unsafe {
        if getuid() != 0 {
            eprintln!("Error: Iron Dome must be run as root.");
            // std::process::exit(1);
        }

        // First fork
        let pid = fork();
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); } // Exit parent

        // Create a new SID for the child process
        if setsid() < 0 { std::process::exit(1); }

        // Second fork (prevents acquiring a controlling terminal)
        let pid = fork();
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); }

        // Set file permissions
        umask(0);

        // Close standard descriptors to complete detach
        close(0);
        close(1);
        close(2);
    }
}
