use std::thread;

use anyhow::Result;
use signal_hook::consts::signal;
use signal_hook::iterator::Signals;

pub fn setup_signal_handlers() -> Result<()> {
    let mut signals = Signals::new([signal::SIGTERM, signal::SIGINT])?;

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                signal::SIGTERM | signal::SIGINT => {
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });

    Ok(())
}
