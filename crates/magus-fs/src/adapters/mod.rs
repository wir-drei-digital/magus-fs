#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod control;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::mount;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{mount, prepare};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn mount(
    _: magus_fs_core::Replica,
    _: &std::path::Path,
    _: &magus_fs_core::RevisionId,
    _: &std::path::Path,
    _: bool,
) -> Result<(), magus_fs_core::FsError> {
    Err(magus_fs_core::FsError::UnsupportedMode)
}
