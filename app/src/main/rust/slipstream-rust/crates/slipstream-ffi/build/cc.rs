use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn resolve_cc(target: &str) -> String {
    if target.contains("android") {
        env::var("RUST_ANDROID_GRADLE_CC")
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string())
    } else {
        env::var("CC").unwrap_or_else(|_| "cc".to_string())
    }
}

pub(crate) fn resolve_ar(target: &str, cc: &str) -> String {
    if target.contains("android") {
        if let Ok(ar) = env::var("RUST_ANDROID_GRADLE_AR") {
            return ar;
        }
    }
    if let Ok(ar) = env::var("AR") {
        return ar;
    }
    if let Some(dir) = Path::new(cc).parent() {
        let candidate = dir.join("llvm-ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        let candidate = dir.join("ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "ar".to_string()
}

pub(crate) fn create_archive(
    ar: &str,
    archive: &Path,
    objects: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(ar);
    command.arg("crus").arg(archive);
    for obj in objects {
        command.arg(obj);
    }
    let status = command.status()?;
    if !status.success() {
        return Err("Failed to create static archive for slipstream objects.".into());
    }
    Ok(())
}

/// Returns extra CC flags needed for cross-compilation (e.g. `-arch x86_64`
/// when building for x86_64 on an ARM64 macOS host).
fn cross_compile_flags() -> Vec<String> {
    let mut flags = Vec::new();
    // Honour CFLAGS from the environment (e.g. `-arch x86_64`).
    if let Ok(cflags) = env::var("CFLAGS") {
        for flag in cflags.split_whitespace() {
            flags.push(flag.to_string());
        }
    }
    flags
}

pub(crate) fn compile_cc(
    cc: &str,
    source: &Path,
    output: &Path,
    picoquic_include_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(cc);
    command
        .arg("-c")
        .arg("-fPIC");
    for flag in cross_compile_flags() {
        command.arg(flag);
    }
    command
        .arg(source)
        .arg("-o")
        .arg(output)
        .arg("-I")
        .arg(picoquic_include_dir);
    let status = command.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}

pub(crate) fn compile_cc_with_includes(
    cc: &str,
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(cc);
    command
        .arg("-c")
        .arg("-fPIC");
    for flag in cross_compile_flags() {
        command.arg(flag);
    }
    command
        .arg(source)
        .arg("-o")
        .arg(output);
    for dir in include_dirs {
        command.arg("-I").arg(dir);
    }
    let status = command.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}
