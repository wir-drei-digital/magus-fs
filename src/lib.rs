pub mod adapters;
pub mod model;
pub mod probe;
pub mod source;
pub use model::{Entry, Manifest};
pub use probe::Probe;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
