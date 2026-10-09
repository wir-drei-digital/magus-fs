use magus_fs_core::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    replica: ReplicaConfig,
    root: PathBuf,
    policy: CapturePolicy,
    creation_umask: u16,
}
pub(crate) type Result<T> = std::result::Result<T, (i32, FsError)>;
fn args(argv: Vec<String>) -> Result<(String, BTreeMap<String, String>)> {
    let command = argv.first().cloned().ok_or((2, FsError::InvalidPath))?;
    let allowed = match command.as_str() {
        "mount" => vec!["state", "revision", "mountpoint", "mode", "source"],
        "init" => vec!["state", "config", "revision-manifest", "source"],
        "capture" => vec!["state", "root", "operation-id"],
        "materialize" => vec!["state", "destination", "revision"],
        "checkpoint" => vec!["state", "operation-id", "expected-generation"],
        "history" | "status" => vec!["state"],
        _ => return Err((2, FsError::InvalidPath)),
    };
    let mut options = BTreeMap::new();
    let mut iter = argv.into_iter().skip(1);
    while let Some(key) = iter.next() {
        let key = key.strip_prefix("--").ok_or((2, FsError::InvalidPath))?;
        if !allowed.contains(&key) {
            return Err((2, FsError::InvalidPath));
        }
        let value = iter.next().ok_or((2, FsError::InvalidPath))?;
        if value.starts_with("--") || options.insert(key.to_string(), value).is_some() {
            return Err((2, FsError::InvalidPath));
        }
    }
    Ok((command, options))
}
fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or((2, FsError::InvalidPath))
}
fn absolute(value: &str) -> Result<&Path> {
    let p = Path::new(value);
    if !p.is_absolute() {
        return Err((2, FsError::InvalidPath));
    }
    Ok(p)
}
fn operation(options: &BTreeMap<String, String>) -> Result<OperationId> {
    OperationId::parse(required(options, "operation-id")?).map_err(|e| (2, e))
}
fn bounded_file(path: &Path) -> std::result::Result<Vec<u8>, FsError> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut bytes = vec![];
    file.take((MAX_DESCRIPTOR + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DESCRIPTOR {
        return Err(FsError::LimitExceeded);
    }
    Ok(bytes)
}
pub fn run(argv: Vec<String>) -> Result<Value> {
    let (command, options) = args(argv)?;
    let state = absolute(required(&options, "state")?)?;
    if command == "init" {
        let config_path = Path::new(required(&options, "config")?);
        let config: Configuration =
            serde_json::from_slice(&bounded_file(config_path).map_err(|e| (2, e))?)
                .map_err(|_| (2, FsError::InvalidDescriptor))?;
        if !config.root.is_absolute() {
            return Err((2, FsError::InvalidPath));
        }
        config.policy.validate().map_err(|e| (2, e))?;
        if !config.replica.content_roots.contains(&config.root) {
            return Err((2, FsError::ConfigMismatch));
        }
        let import = match (options.get("revision-manifest"), options.get("source")) {
            (None, None) => None,
            (Some(file), Some(url)) => {
                let source = if let Some(path) = url.strip_prefix("file://") {
                    ChunkSource::Local {
                        path: absolute(path)?.into(),
                    }
                } else {
                    ChunkSource::Http {
                        base_url: url.clone(),
                    }
                };
                source.validate().map_err(|e| (2, e))?;
                let bytes = bounded_file(Path::new(file)).map_err(|e| (2, e))?;
                let revision = decode_revision(&bytes).map_err(|e| (1, e))?;
                let expected = revision_id(&revision).map_err(|e| (1, e))?;
                Some((ImportDescriptor { expected, bytes }, source))
            }
            _ => return Err((2, FsError::InvalidPath)),
        };
        // Fresh initialization only; reopening always uses the persisted guarded journal config.
        if state.exists() {
            return Err((1, FsError::AlreadyExists));
        }
        let rep = Replica::open(state, config.replica).map_err(|e| (1, e))?;
        rep.configure_native(NativeConfig {
            root: config.root,
            policy: config.policy,
            creation_umask: config.creation_umask,
        })
        .map_err(|e| (1, e))?;
        let actor = rep
            .actor_for_uid(unsafe { libc::geteuid() })
            .map_err(|e| (2, e))?;
        let base = if let Some((descriptor, source)) = import {
            let revision = rep
                .import_revision(descriptor, source)
                .map_err(|e| (1, e))?;
            rep.begin(&revision, actor, false).map_err(|e| (1, e))?;
            Some(revision)
        } else {
            None
        };
        return Ok(json!({"ok":true,"state":state,"base_revision":base}));
    }
    // Validate required argument shapes before taking the owner lock.
    let capture = if command == "capture" {
        Some((
            absolute(required(&options, "root")?)?.to_path_buf(),
            operation(&options)?,
        ))
    } else {
        None
    };
    let material = if command == "materialize" {
        Some((
            absolute(required(&options, "destination")?)?.to_path_buf(),
            RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?,
        ))
    } else {
        None
    };
    let _checkpoint = if command == "checkpoint" {
        Some((
            operation(&options)?,
            options
                .get("expected-generation")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?,
        ))
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    if matches!(command.as_str(), "checkpoint" | "history" | "status") {
        if let Some(response) =
            crate::adapters::control::request(state, &command, &options).map_err(|e| (1, e))?
        {
            if response.exit != 0 {
                eprintln!("magus-fs: {}", response.value["error"]);
                println!("{}", response.value);
                std::process::exit(response.exit);
            }
            return Ok(response.value);
        }
    }
    let rep = Replica::reopen(state).map_err(|e| {
        (
            if matches!(&e,FsError::Io(err)if err.kind()==std::io::ErrorKind::NotFound) {
                2
            } else {
                1
            },
            e,
        )
    })?;
    let actor = rep
        .actor_for_uid(unsafe { libc::geteuid() })
        .map_err(|e| (2, e))?;
    match command.as_str() {
        "capture" => {
            let (root, operation) = capture.unwrap();
            let config = rep
                .native_config()
                .map_err(|e| (1, e))?
                .ok_or((2, FsError::ConfigMismatch))?;
            let revision = rep
                .capture(root, config.policy, operation, actor)
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"revision":revision,"native_metadata":rep.native_metadata_diagnostics().map_err(|e|(1,e))?}),
            )
        }
        "materialize" => {
            let (destination, revision) = material.unwrap();
            let output = rep
                .materialize(&revision, destination, MaterializationMapping { actor })
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"result":output,"recovery":rep.materialization_recovery().map_err(|e|(1,e))?}),
            )
        }
        "mount" => {
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            let mountpoint = absolute(required(&options, "mountpoint")?)?;
            let read_only = match required(&options, "mode")? {
                "read-only" => true,
                "private" => false,
                _ => return Err((2, FsError::InvalidPath)),
            };
            if let Some(url) = options.get("source") {
                let source = if let Some(path) = url.strip_prefix("file://") {
                    ChunkSource::Local {
                        path: absolute(path)?.into(),
                    }
                } else {
                    ChunkSource::Http {
                        base_url: url.clone(),
                    }
                };
                let bytes = encode_revision(&rep.revision(&revision).map_err(|e| (1, e))?)
                    .map_err(|e| (1, e))?;
                rep.import_revision(
                    ImportDescriptor {
                        expected: revision.clone(),
                        bytes,
                    },
                    source,
                )
                .map_err(|e| (1, e))?;
            }
            crate::adapters::mount(rep, state, &revision, mountpoint, read_only)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"unmounted":mountpoint}))
        }
        "checkpoint" | "status" | "history" => control(&rep, actor, &command, &options),
        _ => Err((2, FsError::InvalidPath)),
    }
}
/// Both standalone CLI and mounted owner use exactly these command semantics.
pub(crate) fn control(
    rep: &Replica,
    actor: Actor,
    command: &str,
    options: &BTreeMap<String, String>,
) -> Result<Value> {
    let checkpoint = if command == "checkpoint" {
        Some((
            operation(options)?,
            options
                .get("expected-generation")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?,
        ))
    } else {
        None
    };
    match command {
        "checkpoint" => {
            let status = rep.status().map_err(|e| (1, e))?;
            let base = status.head.ok_or((2, FsError::NotFound))?;
            let workspace = rep.begin(&base, actor, false).map_err(|e| (1, e))?;
            let revision = workspace
                .checkpoint(
                    &checkpoint.as_ref().unwrap().0,
                    checkpoint.as_ref().unwrap().1.unwrap_or(status.generation),
                    Attribution {
                        captured_at_ns: 0,
                        coverage: vec!["".into()],
                        provenance: "engine_observed".into(),
                    },
                )
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"revision":revision}))
        }
        "history" => {
            let mut revisions = vec![];
            for id in rep.history().map_err(|e| (1, e))? {
                let revision = rep.revision(&id).map_err(|e| (1, e))?;
                let canonical = String::from_utf8(encode_revision(&revision).map_err(|e| (1, e))?)
                    .map_err(|_| (1, FsError::InvalidDescriptor))?;
                revisions.push(
                    json!({"revision":id,"descriptor":revision,"canonical_descriptor":canonical}),
                );
            }
            Ok(json!({"ok":true,"revisions":revisions}))
        }
        "status" => {
            let s = rep.status().map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"captured_revision":s.head,"working_generation":s.generation,"uncaptured":if s.dirty{json!(true)}else{json!("unknown")},"base_revision":s.selected_base,"resident_verified_bytes":s.resident_bytes,"missing_bytes":s.missing_bytes,"pinned_recovery_points":s.pinned,"ready_mode":if s.full_ready{"full"}else if s.head.is_some(){"on_demand"}else{"uninitialized"},"materializations":rep.materialization_recovery().map_err(|e|(1,e))?}),
            )
        }
        _ => Err((2, FsError::InvalidPath)),
    }
}
