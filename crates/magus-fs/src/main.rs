mod adapters;
mod cli;
fn main() {
    match cli::run(std::env::args().skip(1).collect()) {
        Ok(value) => println!("{}", value),
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
