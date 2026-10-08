use magus_fs_probe::source::{Fixture, Server};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
fn run() -> magus_fs_probe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
