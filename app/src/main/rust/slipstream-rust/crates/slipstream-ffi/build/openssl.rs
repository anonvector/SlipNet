use crate::util::locate_repo_root;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) struct OpenSslPaths {
    pub(crate) root: Option<PathBuf>,
    pub(crate) include: Option<PathBuf>,
}

pub(crate) fn resolve_openssl_paths() -> OpenSslPaths {
    let allow_env_overrides =
        !cfg!(feature = "openssl-vendored") || env::var_os("OPENSSL_NO_VENDOR").is_some();
    let mut root = None;
    let mut include = None;

    if allow_env_overrides {
        root = env::var("OPENSSL_ROOT_DIR").ok().map(PathBuf::from);
        include = env::var("OPENSSL_INCLUDE_DIR").ok().map(PathBuf::from);
    }

    if root.is_none() {
        root = env::var("DEP_OPENSSL_ROOT").ok().map(PathBuf::from);
    }
    if include.is_none() {
        include = env::var("DEP_OPENSSL_INCLUDE").ok().map(PathBuf::from);
    }

    if root.is_some() || include.is_some() {
        let mut resolved = OpenSslPaths { root, include };
        if cfg!(feature = "openssl-vendored") && !allow_env_overrides {
            if let (Some(target), Some(root)) = (env::var("TARGET").ok(), resolved.root.as_ref()) {
                let root_str = root.to_string_lossy();
                if !root_str.contains(&target) {
                    if let Some(target_paths) = resolve_openssl_from_build_output() {
                        resolved = target_paths;
                    }
                }
            }
        }
        return resolved;
    }

    if cfg!(feature = "openssl-vendored") {
        resolve_openssl_from_build_output().unwrap_or(OpenSslPaths {
            root: None,
            include: None,
        })
    } else {
        OpenSslPaths {
            root: None,
            include: None,
        }
    }
}

fn resolve_openssl_from_build_output() -> Option<OpenSslPaths> {
    let mut build_dirs = candidate_build_dirs();
    if let Some(dir) = locate_cargo_build_dir() {
        build_dirs.push(dir);
    }
    for build_dir in build_dirs {
        if let Some(paths) = find_openssl_sys_in_dir(&build_dir) {
            return Some(paths);
        }
    }
    None
}

fn candidate_build_dirs() -> Vec<PathBuf> {
    let target = env::var("TARGET").ok();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut roots = Vec::new();
    if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        roots.push(PathBuf::from(dir));
    }
    if let Some(root) = locate_repo_root() {
        roots.push(root.join("target"));
    }
    let mut build_dirs = Vec::new();
    for root in roots {
        if let Some(target) = &target {
            build_dirs.push(root.join(target).join(&profile).join("build"));
            build_dirs.push(root.join(target).join("build"));
        }
        build_dirs.push(root.join(&profile).join("build"));
        build_dirs.push(root.join("build"));
    }
    let mut deduped = Vec::new();
    for dir in build_dirs {
        if !deduped.contains(&dir) {
            deduped.push(dir);
        }
    }
    deduped
}

fn find_openssl_sys_in_dir(build_dir: &Path) -> Option<OpenSslPaths> {
    let mut best: Option<(SystemTime, OpenSslPaths)> = None;
    for entry in fs::read_dir(build_dir).ok()? {
        let path = entry.ok()?.path();
        let name = path.file_name()?.to_string_lossy();
        if !name.starts_with("openssl-sys-") {
            continue;
        }
        let output = path.join("output");
        let root_output = path.join("root-output");
        let candidate = parse_openssl_output(&output)
            .or_else(|| parse_openssl_output(&root_output))
            .or_else(|| openssl_paths_from_install(&path));
        let candidate = match candidate {
            Some(candidate) => candidate,
            None => continue,
        };
        let mtime = fs::metadata(&output)
            .and_then(|meta| meta.modified())
            .or_else(|_| fs::metadata(&root_output).and_then(|meta| meta.modified()))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if best.as_ref().map(|(time, _)| mtime > *time).unwrap_or(true) {
            best = Some((mtime, candidate));
        }
    }
    best.map(|(_, paths)| paths)
}

fn locate_cargo_build_dir() -> Option<PathBuf> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").ok()?);
    for ancestor in out_dir.ancestors() {
        if ancestor.file_name().and_then(|name| name.to_str()) == Some("build") {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn parse_openssl_output(path: &Path) -> Option<OpenSslPaths> {
    let contents = fs::read_to_string(path).ok()?;
    let mut root = None;
    let mut include = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("cargo:root=") {
            root = Some(PathBuf::from(value.trim()));
        } else if let Some(value) = line.strip_prefix("cargo:include=") {
            include = Some(PathBuf::from(value.trim()));
        }
    }
    let root = root?;
    Some(OpenSslPaths {
        root: Some(root),
        include,
    })
}

fn openssl_paths_from_install(build_dir: &Path) -> Option<OpenSslPaths> {
    let root = build_dir.join("out").join("openssl-build").join("install");
    let include = root.join("include");
    if !include.join("openssl").exists() {
        return None;
    }
    Some(OpenSslPaths {
        root: Some(root),
        include: Some(include),
    })
}
