//! Instrumentation is compiled only with the non-default test-faults feature.
use crate::FsError;
#[cfg(not(feature = "test-faults"))]
#[inline]
pub(crate) fn hit(_point: &str) -> Result<(), FsError> {
    Ok(())
}
#[cfg(feature = "test-faults")]
pub(crate) fn hit(point: &str) -> Result<(), FsError> {
    if std::env::var("MAGUS_TEST_FAULT_POINT").ok().as_deref() != Some(point) {
        return Ok(());
    }
    match std::env::var("MAGUS_TEST_FAULT_ACTION").as_deref() {
        Ok("delay") => {
            std::thread::sleep(std::time::Duration::from_millis(5));
            Ok(())
        }
        Ok("ENOSPC") => Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into()),
        Ok("EIO") => Err(std::io::Error::from_raw_os_error(libc::EIO).into()),
        Ok("pause") => {
            let marker = std::env::var_os("MAGUS_TEST_FAULT_MARKER").ok_or(FsError::InvalidPath)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(marker)?;
            use std::io::Write;
            f.write_all(point.as_bytes())?;
            f.sync_all()?;
            loop {
                std::thread::park();
            }
        }
        _ => Ok(()),
    }
}
