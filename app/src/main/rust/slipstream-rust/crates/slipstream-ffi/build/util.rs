use std::env;
use std::path::{Path, PathBuf};

pub(crate) fn locate_repo_root() -> Option<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    let crate_dir = Path::new(&manifest_dir);
    Some(crate_dir.parent()?.parent()?.to_path_buf())
}

pub(crate) fn env_flag(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}
