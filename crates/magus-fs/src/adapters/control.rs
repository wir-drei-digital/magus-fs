//! Private owned control channel. Kernel peer credentials, never wire principal IDs.
use magus_fs_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
const LIMIT: u64 = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    command: String,
    options: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Response {
    pub exit: i32,
    pub value: Value,
}
fn peer(stream: &UnixStream) -> Result<u32, FsError> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if len as usize != std::mem::size_of_val(&cred) {
        return Err(FsError::UnsafeStorage);
    }
    Ok(cred.uid)
}
fn directory(state: &Path) -> Result<(), FsError> {
    if !state.is_absolute() {
        return Err(FsError::InvalidPath);
    }
    let mut path = PathBuf::new();
    for c in state.components() {
        if matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return Err(FsError::UnsafeStorage);
        }
        path.push(c);
        let m = fs::symlink_metadata(&path)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(FsError::UnsafeStorage);
        }
    }
    let m = fs::symlink_metadata(state)?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err(FsError::UnsafeStorage);
    }
    Ok(())
}
fn socket_identity(path: &Path) -> Result<(u64, u64), FsError> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok((m.dev(), m.ino()))
}
fn timeouts(stream: &UnixStream) -> Result<(), FsError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}
pub(crate) fn request(
    state: &Path,
    command: &str,
    options: &BTreeMap<String, String>,
) -> Result<Option<Response>, FsError> {
    match directory(state) {
        Ok(()) => {}
        Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let path = state.join("control.sock");
    match socket_identity(&path) {
        Ok(_) => {}
        Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if peer(&stream)? != unsafe { libc::geteuid() } {
        return Err(FsError::PermissionDenied);
    }
    timeouts(&stream)?;
    let bytes = serde_json::to_vec(&Request {
        command: command.into(),
        options: options.clone(),
    })
    .map_err(|_| FsError::InvalidDescriptor)?;
    stream.write_all(&bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = vec![];
    stream.take(LIMIT + 1).read_to_end(&mut response)?;
    if response.len() as u64 > LIMIT {
        return Err(FsError::LimitExceeded);
    }
    Ok(Some(
        serde_json::from_slice(&response).map_err(|_| FsError::InvalidDescriptor)?,
    ))
}
pub(crate) struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    path: PathBuf,
    identity: (u64, u64),
}
impl Server {
    pub fn start(rep: Replica, state: &Path, read_only: bool) -> Result<Self, FsError> {
        directory(state)?;
        rep.configuration()?;
        let path = state.join("control.sock");
        match socket_identity(&path) {
            Ok(_) => {
                match UnixStream::connect(&path) {
                    Ok(_) => return Err(FsError::ReplicaBusy),
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Err(e) => return Err(e.into()),
                }
                // Replica lock is already held: only this owner may reclaim its stale endpoint.
                fs::remove_file(&path)?;
            }
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let identity = socket_identity(&path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let result = (|| {
                            if peer(&stream).map_err(|e| (1, e))? != unsafe { libc::geteuid() } {
                                return Err((1, FsError::PermissionDenied));
                            }
                            timeouts(&stream).map_err(|e| (1, e))?;
                            let mut bytes = vec![];
                            (&mut stream)
                                .take(65537)
                                .read_to_end(&mut bytes)
                                .map_err(|e| (1, FsError::Io(e)))?;
                            if bytes.len() > 65536 {
                                return Err((2, FsError::LimitExceeded));
                            }
                            let request: Request = serde_json::from_slice(&bytes)
                                .map_err(|_| (2, FsError::InvalidDescriptor))?;
                            if !matches!(
                                request.command.as_str(),
                                "checkpoint" | "history" | "status"
                            ) {
                                return Err((2, FsError::InvalidPath));
                            }
                            if read_only && request.command == "checkpoint" {
                                return Err((1, FsError::ReadOnly));
                            }
                            let actor = rep
                                .actor_for_uid(unsafe { libc::geteuid() })
                                .map_err(|e| (1, e))?;
                            crate::cli::control(&rep, actor, &request.command, &request.options)
                        })();
                        let response = match result {
                            Ok(value) => Response { exit: 0, value },
                            Err((exit, error)) => Response {
                                exit,
                                value: json!({"ok":false,"error":error.code(),"details":format!("{error:?}")}),
                            },
                        };
                        if let Ok(bytes) = serde_json::to_vec(&response) {
                            let _ = stream.write_all(&bytes);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
            path,
            identity,
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if socket_identity(&self.path).ok() == Some(self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
