use crate::{Error, Result};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

/// Opens every directory component without following links, then validates the
/// private parent and final file on the actual descriptors (no check/open race).
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::invalid("unsafe_config"));
    }
    let mut dir = File::open("/").map_err(|_| Error::invalid("unsafe_config"))?;
    let parts: Vec<_> = path.components().collect();
    for part in &parts[1..parts.len().saturating_sub(1)] {
        let Component::Normal(s) = part else {
            return Err(Error::invalid("unsafe_config"));
        };
        let name =
            std::ffi::CString::new(s.as_bytes()).map_err(|_| Error::invalid("unsafe_config"))?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::invalid("unsafe_config"));
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    let meta = dir
        .metadata()
        .map_err(|_| Error::invalid("unsafe_config"))?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return Err(Error::invalid("unsafe_config"));
    }
    let name = std::ffi::CString::new(
        path.file_name()
            .ok_or(Error::invalid("unsafe_config"))?
            .as_bytes(),
    )
    .map_err(|_| Error::invalid("unsafe_config"))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(Error::invalid("unsafe_config"));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|_| Error::invalid("unsafe_config"))?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 65_536
    {
        return Err(Error::invalid("unsafe_config"));
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::invalid("unsafe_config"))?;
    if bytes.len() > 65_536 {
        return Err(Error::invalid("unsafe_config"));
    }
    Ok(bytes)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: std::net::SocketAddr,
    pub database: String,
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    #[serde(default)]
    pub private_backend_http: bool,
    pub tls_cert: std::path::PathBuf,
    pub tls_key: std::path::PathBuf,
}
impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| Error::invalid("invalid_config"))?;
        let url = reqwest::Url::parse(&config.s3_endpoint)
            .map_err(|_| Error::invalid("invalid_config"))?;
        if !(url.scheme() == "https" || (config.private_backend_http && url.scheme() == "http"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || config.s3_access_key.is_empty()
            || config.s3_secret_key.is_empty()
        {
            return Err(Error::invalid("invalid_config"));
        }
        Ok(config)
    }
    pub async fn tls(&self) -> Result<axum_server::tls_rustls::RustlsConfig> {
        axum_server::tls_rustls::RustlsConfig::from_pem(
            read_private(&self.tls_cert)?,
            read_private(&self.tls_key)?,
        )
        .await
        .map_err(|_| Error::invalid("invalid_tls"))
    }
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Config([redacted])")
    }
}
