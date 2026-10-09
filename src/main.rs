use magus_fs_probe::source::{Fixture, Server};
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
fn run() -> magus_fs_probe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("mount") {
        return mount(&args[1..]);
    }
    if args.first().map(String::as_str) != Some("source") {
        return Err("usage: magus-fs-probe source --root PATH [--listen ADDRESS] [--chunk-size BYTES] [--mode OCTAL]".into());
    }
    let mut root = None;
    let mut listen = "127.0.0.1:0".to_string();
    let mut chunk = 262144;
    let mut mode = None;
    let mut i = 1;
    while i < args.len() {
        let value = args.get(i + 1).ok_or("missing option value")?;
        match args[i].as_str() {
            "--root" => root = Some(std::path::PathBuf::from(value)),
            "--listen" => listen = value.clone(),
            "--chunk-size" => chunk = value.parse()?,
            "--mode" => mode = Some(u32::from_str_radix(value, 8)?),
            _ => return Err("unknown option".into()),
        }
        i += 2
    }
    let root = root.ok_or("--root required")?;
    let fixture = Fixture::create(&root, chunk, mode)?;
    let server = Server::spawn(fixture, &listen)?;
    println!("{}", server.url());
    loop {
        std::thread::park()
    }
}

fn mount(args: &[String]) -> magus_fs_probe::Result<()> {
    use nfsserve::tcp::{NFSTcp, NFSTcpListener};
    use std::io::Write;
    let mut source = None;
    let mut mountpoint = None;
    let mut mode = None;
    let mut backend = None;
    let mut expected = None;
    let mut prepare = false;
    let mut backing = None;
    let mut resume = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--resume-backing" {
            resume = true;
            i += 1;
            continue;
        }
        if args[i] == "--prepare-only" {
            prepare = true;
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or("missing option value")?;
        match args[i].as_str() {
            "--backing" => backing = Some(std::path::PathBuf::from(value)),
            "--backend" => backend = Some(value.as_str()),
            "--source" => source = Some(value.as_str()),
            "--mountpoint" => mountpoint = Some(std::path::PathBuf::from(value)),
            "--mode" => mode = Some(value.as_str()),
            "--expect-digest" => expected = Some(value.as_str()),
            _ => return Err("unknown mount option".into()),
        }
        i += 2;
    }
    if backend == Some("fuse") {
        if backing.is_some() || resume {
            return Err(
                "FUSE FS0 uses an ephemeral private overlay; backing is unsupported".into(),
            );
        }
        if !matches!(mode, Some("ro" | "private")) {
            return Err("--mode must be ro or private".into());
        }
        #[cfg(target_os = "linux")]
        return magus_fs_probe::adapters::linux::mount(
            source.ok_or("--source required")?,
            &mountpoint.ok_or("--mountpoint required")?,
            mode == Some("private"),
            expected,
            prepare,
        );
        #[cfg(not(target_os = "linux"))]
        return Err("FUSE backend requires Linux".into());
    }
    if backend != Some("nfs") {
        return Err("supported backends: nfs; fuse on Linux".into());
    }
    if !matches!(mode, Some("ro" | "private")) {
        return Err("--mode must be ro or private".into());
    }
    if mode == Some("ro") && (backing.is_some() || resume) {
        return Err("readonly mode does not use backing".into());
    }
    let mut adapter = magus_fs_probe::adapters::macos::NfsAdapter::connect(
        source.ok_or("--source required")?,
        expected,
    )?;
    if mode == Some("private") {
        adapter.enable_private(
            &backing.ok_or("private mode requires --backing for durable FILE_SYNC")?,
            resume,
        )?;
    }
    let hydrated_bytes = adapter.hydrated_bytes();
    let digest = adapter.digest().to_owned();
    let mode = mode.unwrap().to_owned();
    let path = mountpoint.ok_or("--mountpoint required")?;
    if !path.is_absolute() {
        return Err("mountpoint must be an absolute new path".into());
    }
    let parent = path
        .parent()
        .ok_or("mountpoint parent missing")?
        .canonicalize()?;
    let path = parent.join(path.file_name().ok_or("mountpoint basename missing")?);
    std::fs::create_dir(&path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = NFSTcpListener::bind("127.0.0.1:0", adapter).await?;
        let port = listener.get_listen_port();
        let options = format!("{},nolocks,vers=3,tcp,rsize=65536,actimeo=0,soft,timeo=10,retrans=2,port={port},mountport={port}", if mode == "ro" { "ro" } else { "rw" });
        let command = vec!["/sbin/mount_nfs".to_owned(), "-o".into(), options, "127.0.0.1:/".into(), path.to_string_lossy().into_owned()];
        println!("{}", serde_json::json!({"pid":std::process::id(), "port":port, "address":"127.0.0.1", "mode":mode, "hydrated_bytes":hydrated_bytes, "principal_uid":unsafe {libc::geteuid()}, "principal_gid":unsafe {libc::getegid()}, "mountpoint":path, "manifest_digest":digest, "mount_command":command, "prepare_only":prepare}));
        std::io::stdout().flush()?;
        if !prepare {
            let command_copy = command.clone();
            std::thread::spawn(move || {
                match std::process::Command::new(&command_copy[0]).args(&command_copy[1..]).status() {
                    Ok(status) => eprintln!("mount_nfs exited: {status}; server remains available for inspection"),
                    Err(error) => eprintln!("mount_nfs failed: {error}; server remains available for inspection"),
                }
            });
        }
        listener.handle_forever().await?;
        Ok(())
    })
}
