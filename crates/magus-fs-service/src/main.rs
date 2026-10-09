use magus_fs_service::{
    auth,
    config::{read_private, Config},
    serve, ServiceState,
};
use std::path::Path;
#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(error) = run().await {
        eprintln!("{}", error.code);
        std::process::exit(1);
    }
}
async fn run() -> magus_fs_service::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        return Err(magus_fs_service::Error::invalid("usage"));
    }
    let config = Config::read(Path::new(&args[2]))?;
    match args[1].as_str() {
        "provision" if args.len() == 4 => {
            let records = serde_json::from_slice(&read_private(Path::new(&args[3]))?)
                .map_err(|_| magus_fs_service::Error::invalid("invalid_grant"))?;
            let db = magus_fs_service::db::Database::open(config.database).await?;
            auth::provision(&db, records).await?;
            println!("provisioned");
            Ok(())
        }
        "serve" if args.len() == 3 => {
            let tls = config.tls().await?;
            let listener = std::net::TcpListener::bind(config.listen)
                .map_err(|_| magus_fs_service::Error::backend())?;
            let state = ServiceState::open(config).await?;
            serve(state, listener, tls, async {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("signal registration");
                tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}
            })
            .await
            .map_err(|_| magus_fs_service::Error::backend())
        }
        _ => Err(magus_fs_service::Error::invalid("usage")),
    }
}
