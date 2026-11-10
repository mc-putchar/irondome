pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0_usize; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let mut entropy: f64 = 0.0;
    let data_len = data.len() as f64;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / data_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}
