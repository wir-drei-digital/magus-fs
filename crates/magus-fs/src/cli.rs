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
fn args(mut argv: Vec<String>) -> Result<(String, BTreeMap<String, String>)> {
    if argv.first().map(String::as_str) == Some("sync") {
        if argv.len() < 2 {
            return Err((2, FsError::InvalidPath));
        }
        let sub = argv.remove(1);
        argv[0] = format!("sync-{sub}");
        if sub == "recovery" || sub == "conflicts" {
            if argv.len() < 2 || argv[1].starts_with("--") {
                return Err((2, FsError::InvalidPath));
            }
            let action = argv.remove(1);
            argv[0] = format!("sync-{sub}-{action}");
        }
    }
    let command = argv.first().cloned().ok_or((2, FsError::InvalidPath))?;
    let allowed = match command.as_str() {
        "sync-attach" => vec!["state", "profile", "branch", "publication"],
        "sync-run" => vec!["state", "revision", "operation-id", "enqueue-only", "serve"],
        "sync-status" => vec!["state", "revision"],
        "sync-metadata-profile" => vec!["state", "enabled"],
        "sync-declare" => vec!["state", "request"],
        "sync-drain" => vec!["state", "revision", "level", "deadline-ms"],
        "sync-integrate" => vec!["state", "revision", "expected-head"],
        "sync-recovery-list" => vec!["state"],
        "sync-recovery-import" => vec!["state", "archive", "operation-id"],
        "sync-recovery-compare" => vec!["state", "archive"],
        "sync-recovery-capture" => vec!["state", "id", "digest", "operation-id"],
        "sync-recovery-export" => vec!["state", "id", "digest", "destination"],
        "sync-recovery-release" => vec!["state", "operation-id"],
        "sync-recovery-inspect" => vec!["state", "intent-id"],
        "sync-recovery-settle" => vec!["state", "selection", "operation-id"],
        "sync-conflicts-list" => vec!["state", "cursor"],
        "sync-conflicts-show" => vec!["state", "conflict"],
        "sync-conflicts-export" => vec!["state", "conflict", "alternative", "destination"],
        "sync-resolve" => vec![
            "state",
            "conflicts",
            "expected-head",
            "select",
            "choices",
            "replacement",
            "operation-id",
        ],
        "mount" => vec![
            "state",
            "revision",
            "mountpoint",
            "mode",
            "source",
            "prepare-only",
            "nfs-port",
        ],
        "prune" => vec!["state", "dry-run", "token"],
        "export" => vec!["state", "revision", "destination"],
        "verify" => vec!["archive"],
        "restore" => vec![
            "archive",
            "destination",
            "config",
            "state",
            "revision",
            "operation-id",
            "restore-metadata",
        ],
        "history-grants" => vec!["state", "config"],
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
        let value = if key == "dry-run" {
            "true".into()
        } else {
            iter.next().ok_or((2, FsError::InvalidPath))?
        };
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
pub(crate) fn outcome_exit(value: &Value) -> i32 {
    if value["ok"] == false {
        1
    } else {
        0
    }
}
pub fn run(argv: Vec<String>) -> Result<Value> {
    let (command, options) = args(argv)?;
    if command == "verify" {
        return verify_archive(absolute(required(&options, "archive")?)?)
            .map(|v| json!({"ok":true,"verification":v}))
            .map_err(|e| (1, e));
    }
    if command == "restore" && options.contains_key("archive") {
        if options
            .keys()
            .any(|k| !["archive", "destination", "config"].contains(&k.as_str()))
        {
            return Err((2, FsError::InvalidPath));
        }
        let policy: ArchiveRestorePolicy = serde_json::from_slice(
            &bounded_file(absolute(required(&options, "config")?)?).map_err(|e| (2, e))?,
        )
        .map_err(|_| (2, FsError::InvalidDescriptor))?;
        return restore_archive(
            absolute(required(&options, "archive")?)?,
            absolute(required(&options, "destination")?)?,
            policy,
        )
        .map(|v| json!({"ok":true,"result":v}))
        .map_err(|e| (1, e));
    }
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if matches!(command.as_str(), "checkpoint" | "history" | "status")
        || command.starts_with("sync-")
    {
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
    if matches!(
        command.as_str(),
        "mount" | "materialize" | "export" | "restore" | "prune"
    ) {
        crate::sync::install_source(&rep).map_err(|e| (1, e))?;
    }
    let actor = rep
        .actor_for_uid(unsafe { libc::geteuid() })
        .map_err(|e| (2, e))?;
    match command.as_str() {
        "prune" => {
            let result = match (options.get("dry-run"), options.get("token")) {
                (Some(_), None) => rep.prune(true),
                (None, Some(token)) => rep.apply_prune(token),
                _ => return Err((2, FsError::PruneTokenRequired)),
            }
            .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"report":result}))
        }
        "restore" => {
            if options.keys().any(|k| {
                !["state", "revision", "operation-id", "restore-metadata"].contains(&k.as_str())
            }) {
                return Err((2, FsError::InvalidPath));
            }
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            let metadata = match options.get("restore-metadata").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                _ => return Err((2, FsError::InvalidPath)),
            };
            let restored = rep
                .restore_revision(&revision, &operation(&options)?, metadata, actor)
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"source_revision":revision,"revision":restored,"head_changed":true,"materialized":false,"provenance":rep.restore_provenance(&restored).map_err(|e|(1,e))?}),
            )
        }
        "export" => {
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            rep.export(
                &revision,
                absolute(required(&options, "destination")?)?,
                actor,
            )
            .map(|v| json!({"ok":true,"manifest":v}))
            .map_err(|e| (1, e))
        }
        "history-grants" => {
            let grants: Vec<RetainedHistoryGrant> = serde_json::from_slice(
                &bounded_file(absolute(required(&options, "config")?)?).map_err(|e| (2, e))?,
            )
            .map_err(|_| (2, FsError::InvalidDescriptor))?;
            rep.set_retained_history_grants(grants, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true}))
        }
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
            if let Some(value) = options.get("prepare-only") {
                if value != "true" {
                    return Err((2, FsError::InvalidPath));
                }
                #[cfg(target_os = "macos")]
                return crate::adapters::prepare(
                    rep,
                    state,
                    &revision,
                    mountpoint,
                    read_only,
                    options
                        .get("nfs-port")
                        .map(|s| s.parse::<u16>().map_err(|_| (2, FsError::InvalidPath)))
                        .transpose()?
                        .unwrap_or(0),
                )
                .map(|()| json!({"ok":true}))
                .map_err(|e| (1, e));
                #[cfg(not(target_os = "macos"))]
                return Err((2, FsError::UnsupportedMode));
            }
            if options.contains_key("nfs-port") {
                return Err((2, FsError::InvalidPath));
            }
            crate::adapters::mount(rep, state, &revision, mountpoint, read_only)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"unmounted":mountpoint}))
        }
        "checkpoint" | "status" | "history" => control(&rep, actor, &command, &options),
        c if c.starts_with("sync-") => control(&rep, actor, &command, &options),
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
    if command.starts_with("sync-") {
        return sync_control(rep, command, options);
    }
    let actor = if command == "checkpoint" {
        crate::sync::publication_actor(rep, actor).map_err(|e| (1, e))?
    } else {
        actor
    };
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
            // An explicit checkpoint shares capture/publication/incoming execution ownership.
            // Waiting never holds Core, so ordinary mounted writes remain available.
            let execution = crate::sync::SyncExecution::for_replica(
                &rep.configuration().map_err(|e| (1, e))?.replica,
            )
            .map_err(|e| (1, e))?;
            let _gate = execution
                .acquire(std::time::Instant::now() + std::time::Duration::from_secs(5))
                .map_err(|e| (1, e))?
                .ok_or((1, FsError::Backpressure))?;
            // Gate ownership alone is insufficient: replacing an unadmitted head would
            // strand its original operation. Admission failure must leave that head intact.
            crate::sync::admit_engine_checkpoint(rep).map_err(|e| (1, e))?;
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

fn sync_control(rep: &Replica, command: &str, options: &BTreeMap<String, String>) -> Result<Value> {
    use magus_fs_core::protocol::*;
    use std::time::{Duration, Instant};
    if command == "sync-metadata-profile" {
        if std::env::var("MAGUS_METADATA_PROFILE").ok().as_deref() != Some("1") {
            return Err((1, FsError::PermissionDenied));
        }
        let enabled = match required(options, "enabled")? {
            "true" => true,
            "false" => false,
            _ => return Err((2, FsError::InvalidDescriptor)),
        };
        rep.set_metadata_profile_enabled(enabled)
            .map_err(|e| (1, e))?;
        return Ok(json!({"ok":true,"enabled":enabled}));
    }
    let revision = || RevisionId::parse(required(options, "revision")?).map_err(|e| (2, e));
    if command == "sync-attach" {
        let mode = match options.get("publication").map(String::as_str) {
            None | Some("isolated") => PublicationMode::Isolated,
            Some("shared-live") => PublicationMode::SharedLive,
            _ => return Err((2, FsError::InvalidDescriptor)),
        };
        return crate::sync::attach(
            rep,
            absolute(required(options, "profile")?)?,
            BranchName::parse(required(options, "branch")?.into()).map_err(|e| (2, e))?,
            mode,
        )
        .map_err(|e| (1, e));
    }
    if let Some(action) = command.strip_prefix("sync-recovery-") {
        return recovery_control(rep, action, options);
    }
    if command.starts_with("sync-conflicts-") || command == "sync-resolve" {
        return conflicts_control(rep, command, options);
    }
    if command == "sync-declare" {
        return Ok(
            match crate::sync::dependencies::declare(rep, required(options, "request")?) {
                Ok(v) => v,
                Err(e) => json!({"ok":false,"error":e.code}),
            },
        );
    }
    if command == "sync-status" {
        let status = rep.sync_status().map_err(|e| (1, e))?;
        return if options.contains_key("revision") {
            let target = revision()?;
            let p = status
                .submissions
                .into_iter()
                .find(|p| p.local_revision == target)
                .ok_or((2, FsError::NotFound))?;
            Ok(json!({"ok":true,"progress":p}))
        } else {
            Ok(
                json!({"ok":true,"status":status,"live":rep.live_status().ok(),"native":rep.native_status().map_err(|e|(1,e))?}),
            )
        };
    }
    let controller = crate::sync::SyncController::new(rep).map_err(|e| (1, e))?;
    let p = match command {
        "sync-run" => {
            if options.get("serve").map(String::as_str) == Some("true") {
                if options.contains_key("revision")
                    || options.contains_key("operation-id")
                    || options.contains_key("enqueue-only")
                {
                    return Err((2, FsError::InvalidPath));
                }
                let _server = crate::adapters::control::Server::start(
                    rep.clone(),
                    absolute(required(options, "state")?)?,
                    false,
                )
                .map_err(|e| (1, e))?;
                if rep.native_config().map_err(|e| (1, e))?.is_some() {
                    crate::sync::watch::serve(rep).map_err(|e| (1, e))?;
                }
                loop {
                    let _ = controller.tick();
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            if options.contains_key("revision") {
                let target = revision()?;
                let operation = operation(options)?;
                let status = rep.sync_status().map_err(|e| (1, e))?;
                if let Some(old) = status.submissions.iter().find(|p| p.operation == operation) {
                    if old.local_revision != target {
                        return Err((1, FsError::OperationMismatch));
                    }
                } else {
                    let binding = status.binding.ok_or((1, FsError::ConfigMismatch))?;
                    crate::sync::enqueue_submission(
                        rep,
                        PendingSubmission {
                            operation,
                            local_revision: target,
                            original_view: binding.view.view,
                            original_head: binding.view.head,
                            expected_local_generation: rep.status().map_err(|e| (1, e))?.generation,
                        },
                    )
                    .map_err(|e| (1, e))?;
                }
                if options.get("enqueue-only").map(String::as_str) == Some("true") {
                    return Ok(json!({"ok":true,"status":rep.sync_status().map_err(|e|(1,e))?}));
                }
            } else if options.contains_key("operation-id") || options.contains_key("enqueue-only") {
                return Err((2, FsError::InvalidPath));
            }
            controller.tick().map_err(|e| (1, e))?
        }
        "sync-drain" => {
            let level = match required(options, "level")? {
                "local" => DurabilityLevel::Local,
                "private-remote" => DurabilityLevel::PrivateRemote,
                "shared" => DurabilityLevel::Shared,
                "applied" => DurabilityLevel::Applied,
                _ => return Err((2, FsError::InvalidDescriptor)),
            };
            let millis = options
                .get("deadline-ms")
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?
                .unwrap_or(60000);
            if millis > 60000 {
                return Err((2, FsError::LimitExceeded));
            }
            let progress = controller
                .drain(
                    &revision()?,
                    level,
                    Instant::now() + Duration::from_millis(millis),
                )
                .map_err(|e| (1, e))?;
            if !progress.reached(level) {
                let error = if matches!(
                    progress.state,
                    SubmissionState::Denied | SubmissionState::Failed
                ) || crate::sync::held(&progress)
                {
                    progress.error.as_deref().unwrap_or("durability_unmet")
                } else if level == DurabilityLevel::Shared
                    && progress.private_receipt.is_some()
                    && progress.integration.is_none()
                    && rep
                        .sync_status()
                        .map_err(|e| (1, e))?
                        .binding
                        .is_some_and(|b| b.publication == PublicationMode::Isolated)
                {
                    "integration_required"
                } else {
                    "deadline"
                };
                return Ok(
                    json!({"ok":false,"error":error,"requested_level":level,"progress":progress,"counters":controller.counters()}),
                );
            }
            progress
        }
        "sync-integrate" => controller
            .integrate(
                &revision()?,
                HeadToken::parse(required(options, "expected-head")?).map_err(|e| (2, e))?,
            )
            .map_err(|e| (1, e))?,
        _ => return Err((2, FsError::InvalidPath)),
    };
    Ok(json!({"ok":true,"progress":p,"counters":controller.counters()}))
}

/// Immutable service conflicts: listing, inspection, alternative export and resolution.
fn conflicts_control(
    rep: &Replica,
    command: &str,
    options: &BTreeMap<String, String>,
) -> Result<Value> {
    use crate::sync::conflicts;
    use magus_fs_core::protocol::*;
    let conflict = || ConflictId::parse(required(options, "conflict")?).map_err(|e| (2, e));
    let result = match command {
        "sync-conflicts-list" => {
            let cursor = options.get("cursor").map(String::as_str);
            if cursor.is_some_and(|c| c.len() != 32 || !c.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err((2, FsError::InvalidDescriptor));
            }
            conflicts::list(rep, cursor)
        }
        "sync-conflicts-show" => conflicts::show(rep, &conflict()?),
        "sync-conflicts-export" => conflicts::export(
            rep,
            &conflict()?,
            &AlternativeId::parse(required(options, "alternative")?).map_err(|e| (2, e))?,
            absolute(required(options, "destination")?)?,
        ),
        "sync-resolve" => {
            let ids = required(options, "conflicts")?
                .split(',')
                .map(|id| ConflictId::parse(id).map_err(|e| (2, e)))
                .collect::<Result<Vec<_>>>()?;
            if ids.is_empty()
                || ids.len() > MAX_RESOLUTION_CONFLICTS
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
            {
                return Err((2, FsError::InvalidDescriptor));
            }
            let side = |v: &str| match v {
                "base" => Ok(Side::Base),
                "current" => Ok(Side::Left),
                "candidate" => Ok(Side::Right),
                _ => Err((2, FsError::InvalidDescriptor)),
            };
            let default = options.get("select").map(|v| side(v)).transpose()?;
            let mut choices = BTreeMap::new();
            for pair in options
                .get("choices")
                .map(|c| c.split(',').collect::<Vec<_>>())
                .unwrap_or_default()
            {
                let (id, value) = pair
                    .split_once(':')
                    .ok_or((2, FsError::InvalidDescriptor))?;
                let id = ConflictId::parse(id).map_err(|e| (2, e))?;
                if !ids.contains(&id) || choices.insert(id, side(value)?).is_some() {
                    return Err((2, FsError::InvalidDescriptor));
                }
            }
            if default.is_none() && choices.len() != ids.len() {
                return Err((2, FsError::InvalidDescriptor));
            }
            let replacement = options
                .get("replacement")
                .map(|r| RevisionId::parse(r.as_str()).map_err(|e| (2, e)))
                .transpose()?;
            let operation = options
                .get("operation-id")
                .map(|o| OperationId::parse(o.as_str()).map_err(|e| (2, e)))
                .transpose()?;
            conflicts::resolve(
                rep,
                ids,
                HeadToken::parse(required(options, "expected-head")?).map_err(|e| (2, e))?,
                conflicts::Selection {
                    default,
                    choices,
                    replacement,
                },
                operation,
            )
        }
        _ => return Err((2, FsError::InvalidPath)),
    };
    Ok(result.unwrap_or_else(|failure| json!({"ok":false,"error":failure.code})))
}

/// Retained native alternatives are selected only by opaque record id and expected digest.
fn recovery_control(
    rep: &Replica,
    action: &str,
    options: &BTreeMap<String, String>,
) -> Result<Value> {
    let actor = rep
        .actor_for_uid(unsafe { libc::geteuid() })
        .map_err(|e| (2, e))?;
    let id = || NativeRecoveryId::parse(required(options, "id")?).map_err(|e| (2, e));
    let digest = || ObjectId::parse(required(options, "digest")?).map_err(|e| (2, e));
    match action {
        "list" => Ok(
            json!({"ok":true,"records":rep.list_native_recovery(actor.clone()).map_err(|e|(1,e))?,"imports":rep.list_recovery_imports(actor).map_err(|e|(1,e))?,"limit":MAX_RECOVERY_LISTING}),
        ),
        "import" => {
            let archive = absolute(required(options, "archive")?)?;
            let result = rep
                .import_recovery_archive(archive, operation(options)?, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"recovery":result}))
        }
        "compare" => {
            let archive = absolute(required(options, "archive")?)?;
            let changes = rep
                .compare_recovery_archive(archive, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"changed_paths":changes,"published":false}))
        }
        "capture" => {
            let revision = rep
                .capture_native_recovery(id()?, digest()?, operation(options)?, actor)
                .map_err(|e| (1, e))?;
            let descriptor = rep.revision(&revision).map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"revision":revision,"parents":descriptor.parents,"provenance":descriptor.provenance,"published":false}),
            )
        }
        "export" => {
            let destination = absolute(required(options, "destination")?)?;
            rep.export_native_recovery(id()?, digest()?, destination, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"destination":destination}))
        }
        "inspect" => {
            let intent = OperationId::parse(required(options, "intent-id")?).map_err(|e| (2, e))?;
            let selection = rep
                .inspect_native_settlement(intent, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"selection":selection,"published":false}))
        }
        "settle" => {
            let selection: NativeSettlementSelection =
                serde_json::from_str(required(options, "selection")?)
                    .map_err(|_| (2, FsError::InvalidDescriptor))?;
            let receipt = rep
                .settle_native_intent(selection, operation(options)?, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"receipt":receipt,"published":false}))
        }
        "release" => {
            let freed = rep
                .release_native_retention(operation(options)?, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"released_bytes":freed}))
        }
        _ => Err((2, FsError::InvalidPath)),
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use magus_fs_core::protocol::*;
    #[test]
    fn retained_status_does_not_require_transport_files() {
        let root = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-cli-status-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&root).unwrap();
        let state = root.join("state");
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let replica = ReplicaId::random().unwrap();
        let rep = Replica::open(
            &state,
            ReplicaConfig {
                replica: replica.clone(),
                authorities: vec![Authority {
                    principal: principal.clone(),
                    uid: unsafe { libc::geteuid() },
                    primary_group: group.clone(),
                    gid: unsafe { libc::getegid() },
                    groups: vec![group.clone()],
                    dac_override: false,
                    ownership_transfer: false,
                }],
                content_roots: vec![],
                cache_bytes: 1024 * 1024,
                history_administrators: vec![],
                retained_history_grants: vec![],
            },
        )
        .unwrap();
        let r = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica,
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree {
                root: Root {
                    id: EntryId::random().unwrap(),
                    owner: principal,
                    group,
                    mode: 0o755,
                },
                entries: vec![],
            },
        };
        let revision = revision_id(&r).unwrap();
        rep.import_revision(
            ImportDescriptor {
                expected: revision.clone(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        )
        .unwrap();
        rep.configure_sync(SyncBinding {
            id: NamespaceId::random().unwrap(),
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision,
            },
            transport_profile: root.join("missing-profile"),
            transport_identity: TransportIdentity::for_bytes(b"fixture").unwrap(),
        })
        .unwrap();
        drop(rep);
        let result = run(vec![
            "sync".into(),
            "status".into(),
            "--state".into(),
            state.to_str().unwrap().into(),
        ]);
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            result.is_ok(),
            "local retained status must remain accessible: {result:?}"
        );
    }
    #[test]
    fn conflict_commands_select_only_opaque_ids_and_explicit_sides() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let id = "0123456789abcdef0123456789abcdef";
        let (command, options) = args(argv(&[
            "sync",
            "conflicts",
            "export",
            "--state",
            "/s",
            "--conflict",
            id,
            "--alternative",
            id,
            "--destination",
            "/out",
        ]))
        .unwrap();
        assert_eq!(command, "sync-conflicts-export");
        assert_eq!(options["alternative"], id);
        let (command, _) = args(argv(&[
            "sync",
            "resolve",
            "--state",
            "/s",
            "--conflicts",
            id,
            "--expected-head",
            id,
            "--select",
            "candidate",
        ]))
        .unwrap();
        assert_eq!(command, "sync-resolve");
        let (_, options) = args(argv(&[
            "sync",
            "resolve",
            "--state",
            "/s",
            "--conflicts",
            id,
            "--expected-head",
            id,
            "--choices",
            &format!("{id}:current"),
            "--replacement",
            "sha256:00",
        ]))
        .unwrap();
        assert_eq!(options["choices"], format!("{id}:current"));
        for bad in [
            &["sync", "conflicts", "--state", "/s"][..],
            &["sync", "conflicts", "list", "--path", "/x"],
            &["sync", "conflicts", "delete", "--state", "/s"],
            &["sync", "resolve", "--state", "/s", "--content", "/x"],
        ] {
            assert!(args(argv(bad)).is_err(), "{bad:?}");
        }
    }
    #[test]
    fn recovery_commands_select_only_by_opaque_id() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (command, options) =
            args(argv(&["sync", "recovery", "list", "--state", "/s"])).unwrap();
        assert_eq!(command, "sync-recovery-list");
        assert_eq!(options["state"], "/s");
        let (command, _) = args(argv(&[
            "sync",
            "recovery",
            "export",
            "--state",
            "/s",
            "--id",
            "0123456789abcdef0123456789abcdef",
            "--digest",
            "sha256:00",
            "--destination",
            "/out",
        ]))
        .unwrap();
        assert_eq!(command, "sync-recovery-export");
        for bad in [
            &["sync", "recovery", "--state", "/s"][..],
            &["sync", "recovery", "list", "--path", "/retained"],
            &["sync", "recovery", "capture", "--retained", "/x"],
            &["sync", "recovery", "delete", "--state", "/s"],
        ] {
            let parsed = args(argv(bad));
            assert!(
                parsed.is_err() || run(argv(bad)).is_err_and(|e| e.0 == 2),
                "{bad:?}"
            );
        }
    }
    fn admission_fixture(bound: bool) -> (PathBuf, Replica, Workspace, Actor, Option<SyncBinding>) {
        use std::os::unix::fs::PermissionsExt;
        let root = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "checkpoint-order-{}",
            OperationId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let actor = Actor::new(principal.clone());
        let replica = ReplicaId::random().unwrap();
        let rep = Replica::open(
            root.join("state"),
            ReplicaConfig {
                replica: replica.clone(),
                authorities: vec![Authority {
                    principal: principal.clone(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    primary_group: group.clone(),
                    groups: vec![group.clone()],
                    dac_override: false,
                    ownership_transfer: false,
                }],
                content_roots: vec![],
                cache_bytes: 1024 * 1024,
                history_administrators: vec![],
                retained_history_grants: vec![],
            },
        )
        .unwrap();
        let r = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: replica.clone(),
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree {
                root: Root {
                    id: EntryId::random().unwrap(),
                    owner: principal.clone(),
                    group,
                    mode: 0o755,
                },
                entries: vec![],
            },
        };
        let base = revision_id(&r).unwrap();
        rep.import_revision(
            ImportDescriptor {
                expected: base.clone(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        )
        .unwrap();
        let binding = if bound {
            let private = |name: &str, bytes: &[u8]| {
                let p = root.join(name);
                std::fs::write(&p, bytes).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
                p
            };
            let namespace = NamespaceId::random().unwrap();
            let profile = serde_json::json!({"endpoint":"https://localhost:9","namespace":namespace,"replica":replica,"ca_file":private("ca",include_bytes!("../tests/fixtures/client-ca.pem")),"token_file":private("token", "a".repeat(64).as_bytes()),"publication_principal":principal});
            let profile_bytes = serde_json::to_vec(&profile).unwrap();
            let path = private("profile", &profile_bytes);
            // Same canonical immutable profile identity as production load(), without network.
            #[derive(serde::Serialize, serde::Deserialize)]
            struct ProfileIdentity {
                endpoint: String,
                namespace: NamespaceId,
                replica: ReplicaId,
                ca_file: PathBuf,
                token_file: PathBuf,
                publication_principal: PrincipalId,
            }
            let normalized: ProfileIdentity = serde_json::from_value(profile).unwrap();
            let ca =
                ObjectId::for_bytes(include_bytes!("../tests/fixtures/client-ca.pem")).unwrap();
            let identity =
                TransportIdentity::for_bytes(&serde_json::to_vec(&(normalized, ca)).unwrap())
                    .unwrap();
            let b = SyncBinding {
                id: namespace,
                branch: BranchName::parse("main".into()).unwrap(),
                publication: PublicationMode::SharedLive,
                source: RemoteSourceId::random().unwrap(),
                view: ViewBinding {
                    view: ViewId::random().unwrap(),
                    head: HeadToken::random().unwrap(),
                    revision: base.clone(),
                },
                transport_profile: path,
                transport_identity: identity,
            };
            rep.configure_sync(b.clone()).unwrap();
            Some(b)
        } else {
            None
        };
        let ws = rep.begin(&base, actor.clone(), false).unwrap();
        (root, rep, ws, actor, binding)
    }
    fn explicit_checkpoint(rep: &Replica, actor: Actor, operation: OperationId) -> Result<Value> {
        control(
            rep,
            actor,
            "checkpoint",
            &BTreeMap::from([("operation-id".into(), operation.as_str().into())]),
        )
    }
    #[test]
    fn checkpoint_admission_orders_two_controls_and_control_first_after_restart() {
        let (root, rep, ws, actor, binding) = admission_fixture(true);
        let binding = binding.unwrap();
        let operation = OperationId::random().unwrap();
        let first = explicit_checkpoint(&rep, actor.clone(), operation.clone()).unwrap();
        let first = RevisionId::parse(first["revision"].as_str().unwrap().to_owned()).unwrap();
        assert!(rep.pending_submissions().unwrap().is_empty());
        drop(ws);
        drop(rep);
        let rep = Replica::reopen(root.join("state")).unwrap();
        let second =
            explicit_checkpoint(&rep, actor.clone(), OperationId::random().unwrap()).unwrap();
        let pending = rep.pending_submissions().unwrap();
        assert!(
            pending.iter().any(|p| p.operation == operation
                && p.local_revision == first
                && p.original_view == binding.view.view
                && p.original_head == binding.view.head),
            "control-first checkpoint must admit the original capture before replacing its head"
        );
        assert_ne!(second["revision"].as_str().unwrap(), first.as_str());
        let second_id = RevisionId::parse(second["revision"].as_str().unwrap().to_owned()).unwrap();
        explicit_checkpoint(&rep, actor, OperationId::random().unwrap()).unwrap();
        assert!(
            rep.pending_submissions()
                .unwrap()
                .iter()
                .any(|p| p.local_revision == second_id),
            "second checkpoint before any capture tick must also survive"
        );
        drop(rep);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn checkpoint_admission_backpressure_preserves_head_operation_and_generation() {
        let (root, rep, ws, actor, binding) = admission_fixture(true);
        let binding = binding.unwrap();
        for _ in 0..128 {
            let mut r = rep.revision(&binding.view.revision).unwrap();
            r.parents = vec![binding.view.revision.clone()];
            r.operation = OperationId::random().unwrap();
            r.provenance = "engine_observed".into();
            let id = rep
                .import_revision(
                    ImportDescriptor {
                        expected: revision_id(&r).unwrap(),
                        bytes: encode_revision(&r).unwrap(),
                    },
                    ChunkSource::Unavailable,
                )
                .unwrap();
            rep.enqueue_submission(PendingSubmission {
                operation: r.operation,
                local_revision: id,
                original_view: binding.view.view.clone(),
                original_head: binding.view.head.clone(),
                expected_local_generation: rep.status().unwrap().generation,
            })
            .unwrap();
        }
        let original_op = OperationId::random().unwrap();
        let original = explicit_checkpoint(&rep, actor.clone(), original_op.clone()).unwrap();
        let generation = rep.status().unwrap().generation;
        let replacement = OperationId::random().unwrap();
        let result = explicit_checkpoint(&rep, actor, replacement.clone());
        assert!(
            matches!(result, Err((1, FsError::Backpressure))),
            "checkpoint must fail admission before replacing the captured head: {result:?}"
        );
        assert_eq!(rep.status().unwrap().generation, generation);
        assert_eq!(
            rep.status().unwrap().head.unwrap().as_str(),
            original["revision"].as_str().unwrap()
        );
        assert!(rep
            .status()
            .unwrap()
            .operations
            .iter()
            .all(|o| o.operation != replacement));
        assert_eq!(
            rep.revision(&rep.status().unwrap().head.unwrap())
                .unwrap()
                .operation,
            original_op
        );
        drop(ws);
        drop(rep);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn checkpoint_admission_unbound_snapshot_still_accepts_successive_checkpoints() {
        let (root, rep, ws, actor, _) = admission_fixture(false);
        explicit_checkpoint(&rep, actor.clone(), OperationId::random().unwrap()).unwrap();
        explicit_checkpoint(&rep, actor, OperationId::random().unwrap()).unwrap();
        assert!(rep.pending_submissions().unwrap().is_empty());
        drop(ws);
        drop(rep);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_admission_interleaved_write_keeps_admitted_original_and_dirty_bytes() {
        let (root, rep, ws, actor, binding) = admission_fixture(true);
        let binding = binding.unwrap();
        let original_op = OperationId::random().unwrap();
        let original = explicit_checkpoint(&rep, actor.clone(), original_op.clone()).unwrap();
        let observed = rep.status().unwrap().generation;
        let handle = ws.create("interleaved", 0o600).unwrap();
        ws.write(&handle, 0, b"dirty generation after caller observation")
            .unwrap();
        let written = rep.status().unwrap().generation;
        let replacement = OperationId::random().unwrap();
        let options = BTreeMap::from([
            ("operation-id".into(), replacement.as_str().into()),
            ("expected-generation".into(), observed.to_string()),
        ]);
        assert!(matches!(
            control(&rep, actor, "checkpoint", &options),
            Err((1, FsError::GenerationMismatch))
        ));
        assert_eq!(
            rep.status().unwrap().head.unwrap().as_str(),
            original["revision"].as_str().unwrap()
        );
        assert_eq!(rep.status().unwrap().generation, written);
        assert!(rep.status().unwrap().dirty);
        assert_eq!(
            ws.read(&handle, 0, 100).unwrap(),
            b"dirty generation after caller observation"
        );
        assert!(rep
            .pending_submissions()
            .unwrap()
            .iter()
            .any(|p| p.operation == original_op
                && p.original_view == binding.view.view
                && p.original_head == binding.view.head));
        assert!(rep
            .status()
            .unwrap()
            .operations
            .iter()
            .all(|o| o.operation != replacement));
        drop(handle);
        drop(ws);
        drop(rep);
        std::fs::remove_dir_all(root).unwrap();
    }
}
