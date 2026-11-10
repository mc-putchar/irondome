use std::io::Read;

use anyhow::Result;

pub fn calculate_file_entropy<R: Read>(mut reader: R) -> Result<f64> {
    let mut frequency = [0_usize; 256];
    let mut total_bytes = 0_usize;
    let mut buf = [0_u8; 65536];

    // Reading cap at 4 MB per file
    const MAX_SAMPLE_BYTES: usize = 4 * 1024 * 1024;

    while total_bytes < MAX_SAMPLE_BYTES {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            frequency[byte as usize] += 1;
        }
        total_bytes += n;
    }

    if total_bytes == 0 {
        return Ok(0.0);
    }

    let mut entropy = 0.0_f64;
    let len_f64 = total_bytes as f64;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len_f64;
            entropy -= probability * probability.log2();
        }
    }

    Ok(entropy)
}
