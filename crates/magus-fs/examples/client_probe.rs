//! Test journey helper using the production transport and only public engine APIs.
#[path = "../src/sync/transport.rs"]
#[allow(dead_code)]
mod transport;
use magus_fs_core::*;
use std::{io::Write, sync::Arc};
fn run() -> Result<serde_json::Value, FsError> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let rep = Replica::reopen(&args[0])?;
    let binding = rep.sync_status()?.binding.ok_or(FsError::ConfigMismatch)?;
    let t = Arc::new(transport::Transport::new(binding, &rep.configuration()?)?);
    rep.set_remote_fetcher(t.clone())?;
    let head = rep.status()?.head.ok_or(FsError::NotFound)?;
    let w = rep.begin(&head, rep.actor_for_uid(unsafe { libc::geteuid() })?, false)?;
    let value = match args[1].as_str() {
        "read" => {
            let h = w.open(&args[2], OpenMode::Read)?;
            let offset = args[3].parse::<u64>().unwrap();
            let length = args[4].parse::<usize>().unwrap();
            let bytes = match w.read(&h, offset, length) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Ok(
                        serde_json::json!({"ok":false,"error":e.code(),"counters":*t.counters.lock().unwrap()}),
                    )
                }
            };
            let hash = ObjectId::for_bytes(&bytes)?;
            std::fs::write(&args[5], &bytes)?;
            serde_json::json!({"bytes":bytes.len(),"hash":hash})
        }
        "full" => {
            let h = w.open(&args[2], OpenMode::Read)?;
            let mut file = std::fs::File::create(&args[3])?;
            let mut offset = 0;
            loop {
                let bytes = w.read(&h, offset, 262144)?;
                if bytes.is_empty() {
                    break;
                }
                file.write_all(&bytes)?;
                offset += bytes.len() as u64;
            }
            serde_json::json!({"bytes":offset})
        }
        "write" => {
            let h = match w.open(&args[2], OpenMode::ReadWrite) {
                Ok(h) => h,
                Err(FsError::NotFound) => w.create(&args[2], 0o600)?,
                Err(e) => return Err(e),
            };
            w.truncate(&h, 0)?;
            w.write(&h, 0, args[3].as_bytes())?;
            serde_json::json!({"generation":w.generation()?})
        }
        _ => return Err(FsError::InvalidPath),
    };
    Ok(serde_json::json!({"ok":true,"result":value,"counters":*t.counters.lock().unwrap()}))
}
fn main() {
    match run() {
        Ok(v) => println!("{v}"),
        Err(e) => {
            println!("{}", serde_json::json!({"ok":false,"error":e.code()}));
            std::process::exit(1);
        }
    }
}
