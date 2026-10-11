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
    // Bounded, configuration-free text merge worker spawned (and killed) by the service.
    if args.len() == 2 && args[1] == magus_fs_service::reconciliation::WORKER_ARG {
        std::process::exit(magus_fs_service::reconciliation::worker_main());
    }
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
        "repair"
            if args.len() == 9
                && args[3] == "--namespace"
                && args[5] == "--object"
                && args[7] == "--source" =>
        {
            let namespace = magus_fs_core::protocol::NamespaceId::parse(&args[4])
                .map_err(|_| magus_fs_service::Error::invalid("invalid_id"))?;
            let object = magus_fs_core::ObjectId::parse(&args[6])
                .map_err(|_| magus_fs_service::Error::invalid("invalid_id"))?;
            let bytes = magus_fs_service::config::read_private_bounded(
                Path::new(&args[8]),
                magus_fs_core::MAX_CHUNK,
            )?;
            let state = ServiceState::open(config).await?;
            let generation = state
                .objects
                .repair(&namespace, &object, bytes.into())
                .await?;
            println!(
                "{}",
                serde_json::json!({"repaired":true,"object":object,"generation":generation})
            );
            Ok(())
        }
        "gc" if (args.len() == 6 || args.len() == 7) && args[3] == "--namespace" => {
            let namespace = magus_fs_core::protocol::NamespaceId::parse(&args[4])
                .map_err(|_| magus_fs_service::Error::invalid("invalid_id"))?;
            let state = ServiceState::open(config).await?;
            let result = if args.len() == 6 && args[5] == "--dry-run" {
                serde_json::to_string(
                    &magus_fs_service::retention::dry_run(&state, &namespace).await?,
                )
            } else if args.len() == 7 && args[5] == "--plan" {
                serde_json::to_string(
                    &magus_fs_service::retention::execute(&state, &namespace, &args[6]).await?,
                )
            } else {
                return Err(magus_fs_service::Error::invalid("usage"));
            };
            println!(
                "{}",
                result.map_err(|_| magus_fs_service::Error::backend())?
            );
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
