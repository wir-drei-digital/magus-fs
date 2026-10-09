mod adapters;
mod cli;
mod sync;
fn main() {
    match cli::run(std::env::args().skip(1).collect()) {
        Ok(value) => {
            let exit = cli::outcome_exit(&value);
            println!("{}", value);
            if exit != 0 {
                std::process::exit(exit);
            }
        }
        Err((exit, error)) => {
            eprintln!("magus-fs: {}", error);
            println!(
                "{}",
                serde_json::json!({"ok":false,"error":error.code(),"details":format!("{error:?}")})
            );
            std::process::exit(exit);
        }
    }
}
