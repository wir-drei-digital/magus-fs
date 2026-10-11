//! Dedicated immutable declaration operation; request JSON is bounded and caller-owned.
use super::transport::{Failure, Transport};
use magus_fs_core::{protocol::*, *};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
pub(crate) fn declare(rep: &Replica, request: &str) -> Result<Value, Failure> {
    if request.len() > MAX_CONTROL {
        return Err(FsError::LimitExceeded.into());
    }
    let req: DeclareRequest =
        serde_json::from_str(request).map_err(|_| FsError::InvalidDescriptor)?;
    req.validate()?;
    let binding = rep.sync_status()?.binding.ok_or(FsError::ConfigMismatch)?;
    let config = rep.configuration()?;
    if req.replica != config.replica {
        return Err(FsError::OperationMismatch.into());
    }
    let t = Transport::new(binding, &config)?;
    let receipt: DeclarationReceipt = t.json(
        "POST",
        "/declarations",
        &req,
        Instant::now() + Duration::from_secs(10),
    )?;
    Ok(json!({"ok":true,"declaration":receipt}))
}
