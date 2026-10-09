#[cfg(target_os = "linux")]
pub(crate) mod control;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::mount;
#[cfg(not(target_os = "linux"))]
pub fn mount(
    _: magus_fs_core::Replica,
    _: &std::path::Path,
    _: &magus_fs_core::RevisionId,
    _: &std::path::Path,
    _: bool,
) -> Result<(), magus_fs_core::FsError> {
    Err(magus_fs_core::FsError::UnsupportedMode)
}
