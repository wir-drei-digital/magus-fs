//! Measured candidate chunk layout, not a durable format or a filesystem API.
use fastcdc::v2020::{Normalization, StreamCDC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::time::Instant;

#[derive(Serialize, Deserialize)]
struct Descriptor {
    offset: u64,
    length: u64,
    sha256: String,
}

fn usage() -> libc::rusage {
    // getrusage writes the initialized native structure; SELF owns this process.
    unsafe {
        let mut value: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut value), 0);
        value
    }
}

fn cpu(value: &libc::rusage) -> f64 {
    value.ru_utime.tv_sec as f64
        + value.ru_utime.tv_usec as f64 / 1e6
        + value.ru_stime.tv_sec as f64
        + value.ru_stime.tv_usec as f64 / 1e6
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 || !["fixed", "cdc"].contains(&args[2].as_str()) {
        return Err("usage: chunk_layout INPUT fixed|cdc [BASE_REPORT]".into());
    }
    let start = Instant::now();
    let before = usage();
    let base: HashMap<String, u64> = if let Some(path) = args.get(3) {
        let value: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
        let descriptors: Vec<Descriptor> = serde_json::from_value(value["descriptors"].clone())?;
        descriptors
            .into_iter()
            .map(|d| (d.sha256, d.length))
            .collect()
    } else {
        HashMap::new()
    };
    let mut input = File::open(&args[1])?;
    let mut descriptors = Vec::new();
    let mut digest = Sha256::new();
    let mut seen = HashSet::new();
    let mut new_bytes = 0;
    let mut scanned = 0;
    let mut encoded = Vec::new();
    let mut record = |offset: u64, bytes: &[u8]| {
        let hash = Sha256::digest(bytes);
        let identity = format!("{hash:x}");
        digest.update(bytes);
        scanned += bytes.len() as u64;
        if !base.contains_key(&identity) && seen.insert(identity.clone()) {
            new_bytes += bytes.len() as u64;
        }
        // The candidate's actual 48-byte descriptor encoding is measured. This
        // is expressly not final-format storage/index/envelope overhead.
        encoded.extend_from_slice(&offset.to_le_bytes());
        encoded.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&hash);
        descriptors.push(Descriptor {
            offset,
            length: bytes.len() as u64,
            sha256: identity,
        });
    };
    if args[2] == "cdc" {
        for chunk in StreamCDC::with_level(input, 65536, 262144, 1048576, Normalization::Level1) {
            let chunk = chunk?;
            record(chunk.offset, &chunk.data);
        }
    } else {
        let mut offset = 0;
        loop {
            let mut buffer = Vec::with_capacity(262144);
            input.by_ref().take(262144).read_to_end(&mut buffer)?;
            if buffer.is_empty() {
                break;
            }
            record(offset, &buffer);
            offset += buffer.len() as u64;
        }
    }
    let hash = format!("{:x}", digest.finalize());
    let after = usage();
    let elapsed = start.elapsed().as_secs_f64();
    let rss_scale = if cfg!(target_os = "macos") { 1 } else { 1024 };
    let report = serde_json::json!({
        "layout": args[2], "sha256": hash,
        "bytes_scanned_rechunked": scanned,
        "unique_new_bytes": new_bytes, "transferred_bytes": new_bytes,
        "descriptor_count": descriptors.len(), "descriptor_encoded_bytes": encoded.len(),
        "descriptors": descriptors, "cpu_seconds": cpu(&after) - cpu(&before),
        "elapsed_seconds": elapsed, "peak_rss_bytes": after.ru_maxrss * rss_scale,
        "timing_scope": "open/base-index-read + full streaming chunk/hash/dedup + actual candidate descriptor encoding; excludes diagnostic JSON and independent verification"
    });
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
